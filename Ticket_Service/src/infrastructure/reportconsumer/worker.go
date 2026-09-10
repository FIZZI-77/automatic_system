package reportconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"ticket/pkg/telemetry"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

type Worker struct {
	db     *pgxpool.Pool
	reader *kafka.Reader
	writer *kafka.Writer
	topic  string
	logger *zap.Logger
}

type resultEvent struct {
	WorkReportID string   `json:"work_report_id"`
	FileID       string   `json:"file_id"`
	Error        string   `json:"error"`
	RequestedBy  string   `json:"requested_by"`
	ActorRoles   []string `json:"actor_roles"`
}

type poisonError struct {
	err error
}

func (e poisonError) Error() string {
	return e.err.Error()
}

func (e poisonError) Unwrap() error {
	return e.err
}

func New(
	db *pgxpool.Pool,
	brokers []string,
	topic string,
	groupID string,
	logger *zap.Logger,
) (*Worker, error) {
	if db == nil || len(brokers) == 0 || strings.TrimSpace(topic) == "" || strings.TrimSpace(groupID) == "" {
		return nil, errors.New("report consumer: db, brokers, topic and group id are required")
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Topic:          topic,
		GroupID:        groupID,
		CommitInterval: 0,
		MinBytes:       1,
		MaxBytes:       10e6,
	})
	writer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		RequiredAcks: kafka.RequireAll,
	}

	return &Worker{
		db:     db,
		reader: reader,
		writer: writer,
		topic:  topic,
		logger: logger,
	}, nil
}

func (w *Worker) Close() error {
	return errors.Join(w.reader.Close(), w.writer.Close())
}

func (w *Worker) Run(ctx context.Context) error {
	for {
		message, err := w.reader.FetchMessage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			w.logger.Warn("fetch report result failed; retrying", zap.Error(err))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
				continue
			}
		}
		if err = telemetry.TraceKafkaConsumer(ctx, message, "", w.apply); err != nil {
			var invalid poisonError
			if !errors.As(err, &invalid) && !errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("apply report result: %w", err)
			}
			w.logger.Error("poison report result moved to DLQ", zap.Error(err))
			if dlqErr := w.publishDLQ(ctx, message, err); dlqErr != nil {
				return errors.Join(err, dlqErr)
			}
		}
		if err = w.reader.CommitMessages(ctx, message); err != nil {
			return fmt.Errorf("commit report result: %w", err)
		}
	}
}

func (w *Worker) publishDLQ(ctx context.Context, message kafka.Message, processErr error) (err error) {
	ctx, span := telemetry.Tracer("ticket/dlq").Start(ctx, "DLQ.Publish")
	defer func() { telemetry.End(span, err) }()
	span.SetAttributes(
		attribute.String("messaging.destination.name", w.topic+".dlq"),
		attribute.String("messaging.operation.name", "publish"),
	)

	headers := append([]kafka.Header(nil), message.Headers...)
	headers = append(headers, kafka.Header{
		Key:   "x-error",
		Value: []byte(truncate(processErr.Error(), 1000)),
	})

	return telemetry.WriteKafka(ctx, w.writer, kafka.Message{
		Topic:   w.topic + ".dlq",
		Key:     message.Key,
		Value:   message.Value,
		Headers: headers,
	})
}

func (w *Worker) apply(ctx context.Context, message kafka.Message) (err error) {
	eventType := header(message.Headers, "event_type")
	if eventType != "ticket.completion_report.generated.v1" &&
		eventType != "ticket.completion_report.failed.v1" &&
		eventType != "ticket.completion_report.compensated.v1" &&
		eventType != "ticket.completion_report.compensation_failed.v1" {
		return nil
	}
	ctx, span := telemetry.Tracer("ticket/completion-saga").Start(ctx, "CompletionSaga.ApplyResult")
	defer func() { telemetry.End(span, err) }()
	span.SetAttributes(
		attribute.String("saga.name", "completion_report"),
		attribute.String("messaging.event.type", eventType),
	)
	eventID, err := uuid.Parse(header(message.Headers, "event_id"))
	if err != nil {
		return poisonError{err: fmt.Errorf("invalid result event id: %w", err)}
	}
	var payload resultEvent
	if err = json.Unmarshal(message.Value, &payload); err != nil {
		return poisonError{err: fmt.Errorf("decode report result: %w", err)}
	}
	workReportID, err := uuid.Parse(payload.WorkReportID)
	if err != nil {
		return poisonError{err: fmt.Errorf("invalid work report id: %w", err)}
	}
	tx, err := w.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var inserted uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO completion_report_inbox(event_id) VALUES($1) ON CONFLICT DO NOTHING RETURNING event_id`, eventID).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	switch eventType {
	case "ticket.completion_report.generated.v1":
		fileID, parseErr := uuid.Parse(payload.FileID)
		if parseErr != nil {
			return poisonError{err: fmt.Errorf("invalid completion file id: %w", parseErr)}
		}
		err = w.applyGenerated(ctx, tx, workReportID, fileID, payload)
	case "ticket.completion_report.failed.v1":
		_, err = tx.Exec(ctx, `
			UPDATE ticket_reports
			SET completion_error=$2, completion_deadline_at=now(), completion_updated_at=now(), updated_at=now()
			WHERE id=$1 AND completion_status='PENDING'`, workReportID, truncate(payload.Error, 2000))
	case "ticket.completion_report.compensated.v1":
		_, err = tx.Exec(ctx, `
			UPDATE ticket_reports
			SET completion_status='COMPENSATED', completion_file_id=NULL, completion_error=NULL,
				completion_deadline_at=NULL, completion_updated_at=now(), updated_at=now()
			WHERE id=$1 AND completion_status='COMPENSATING'`, workReportID)
	case "ticket.completion_report.compensation_failed.v1":
		err = w.retryCompensation(ctx, tx, workReportID, payload)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (w *Worker) applyGenerated(
	ctx context.Context,
	tx pgx.Tx,
	workReportID uuid.UUID,
	fileID uuid.UUID,
	payload resultEvent,
) error {
	var status string
	var currentFileID *uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT completion_status, completion_file_id
		FROM ticket_reports
		WHERE id=$1
		FOR UPDATE`, workReportID).Scan(&status, &currentFileID)
	if err != nil {
		return err
	}

	if status == "PENDING" {
		_, err = tx.Exec(ctx, `
			UPDATE ticket_reports
			SET completion_status='COMPLETED', completion_file_id=$2, completion_error=NULL,
				completion_deadline_at=NULL, completion_updated_at=now(), updated_at=now()
			WHERE id=$1`, workReportID, fileID)
		return err
	}
	if status == "COMPLETED" && currentFileID != nil && *currentFileID == fileID {
		return nil
	}

	compensation, err := json.Marshal(map[string]any{
		"work_report_id": workReportID,
		"file_id":        fileID,
		"requested_by":   payload.RequestedBy,
		"actor_roles":    payload.ActorRoles,
		"cleanup_only":   status == "COMPLETED",
	})
	if err != nil {
		return fmt.Errorf("encode completion compensation: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload)
		VALUES($1,'ticket_report',$2,'ticket.completion_report.compensation_requested.v1',$3)`,
		uuid.New(), workReportID, compensation)
	if err != nil {
		return err
	}
	if status != "COMPLETED" {
		_, err = tx.Exec(ctx, `
			UPDATE ticket_reports
			SET completion_status='COMPENSATING', completion_file_id=$2,
				completion_compensation_attempts=1, completion_updated_at=now(), updated_at=now()
			WHERE id=$1`, workReportID, fileID)
	}
	return err
}

func (w *Worker) retryCompensation(
	ctx context.Context,
	tx pgx.Tx,
	workReportID uuid.UUID,
	payload resultEvent,
) error {
	var status string
	var attempts int
	err := tx.QueryRow(ctx, `
		SELECT completion_status, completion_compensation_attempts
		FROM ticket_reports
		WHERE id=$1
		FOR UPDATE`, workReportID).Scan(&status, &attempts)
	if err != nil || status != "COMPENSATING" {
		return err
	}
	if attempts >= 3 {
		_, err = tx.Exec(ctx, `
			UPDATE ticket_reports
			SET completion_status='FAILED', completion_error=$2,
				completion_updated_at=now(), updated_at=now()
			WHERE id=$1`, workReportID, "compensation failed: "+truncate(payload.Error, 1800))
		return err
	}

	compensation, err := json.Marshal(map[string]any{
		"work_report_id": workReportID,
		"file_id":        payload.FileID,
		"requested_by":   payload.RequestedBy,
		"actor_roles":    payload.ActorRoles,
	})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload)
		VALUES($1,'ticket_report',$2,'ticket.completion_report.compensation_requested.v1',$3)`,
		uuid.New(), workReportID, compensation)
	if err == nil {
		_, err = tx.Exec(ctx, `
			UPDATE ticket_reports
			SET completion_compensation_attempts=completion_compensation_attempts+1,
				completion_error=$2, completion_updated_at=now(), updated_at=now()
			WHERE id=$1`, workReportID, truncate(payload.Error, 2000))
	}
	return err
}

func header(headers []kafka.Header, key string) string {
	for _, value := range headers {
		if strings.EqualFold(value.Key, key) {
			return string(value.Value)
		}
	}
	return ""
}

func truncate(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}
	return value[:maxLen]
}
