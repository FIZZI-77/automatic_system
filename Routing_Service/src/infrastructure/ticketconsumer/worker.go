package ticketconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

const retryHeader = "x-retry-count"

type Config struct {
	Brokers []string
	Topic   string
	GroupID string
	Workers int
}

type Worker struct {
	db        *pgxpool.Pool
	readers   []*kafka.Reader
	retry     *kafka.Reader
	writer    *kafka.Writer
	topic     string
	logger    *zap.Logger
	closeOnce sync.Once
}

type routeEvent struct {
	ID        string    `json:"id"`
	TicketID  string    `json:"ticket_id"`
	BrigadeID string    `json:"brigade_id"`
	Status    string    `json:"status"`
	Revision  int32     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
}

func New(db *pgxpool.Pool, cfg Config, logger *zap.Logger) (*Worker, error) {
	cfg.Brokers = clean(cfg.Brokers)
	if db == nil || len(cfg.Brokers) == 0 || strings.TrimSpace(cfg.Topic) == "" || strings.TrimSpace(cfg.GroupID) == "" {
		return nil, errors.New("ticket consumer: db, brokers, topic and group id are required")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	newReader := func(topic, group string) *kafka.Reader {
		return kafka.NewReader(kafka.ReaderConfig{Brokers: cfg.Brokers, Topic: topic, GroupID: group, MinBytes: 1, MaxBytes: 10e6, CommitInterval: 0})
	}
	w := &Worker{
		db: db, topic: cfg.Topic, logger: logger,
		readers: make([]*kafka.Reader, 0, cfg.Workers),
		retry:   newReader(cfg.Topic+".retry", cfg.GroupID+".retry"),
		writer:  &kafka.Writer{Addr: kafka.TCP(cfg.Brokers...), RequiredAcks: kafka.RequireAll},
	}
	for range cfg.Workers {
		w.readers = append(w.readers, newReader(cfg.Topic, cfg.GroupID))
	}
	return w, nil
}

func (w *Worker) Run(ctx context.Context) error {
	errs := make(chan error, len(w.readers)+1)
	for _, reader := range append(w.readers, w.retry) {
		go func(r *kafka.Reader) { errs <- w.consume(ctx, r) }(reader)
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		return err
	}
}

func (w *Worker) Close() error {
	var result error
	w.closeOnce.Do(func() {
		for _, reader := range append(w.readers, w.retry) {
			result = errors.Join(result, reader.Close())
		}
		result = errors.Join(result, w.writer.Close())
	})
	return result
}

func (w *Worker) consume(ctx context.Context, reader *kafka.Reader) error {
	for {
		message, err := reader.FetchMessage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			return fmt.Errorf("fetch ticket event: %w", err)
		}
		if strings.HasSuffix(message.Topic, ".retry") {
			timer := time.NewTimer(time.Duration(1<<min(retries(message.Headers), 5)) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
		if err = w.apply(ctx, message); err != nil {
			w.logger.Error("ticket event processing failed", zap.Error(err), zap.Int64("offset", message.Offset))
			if retryErr := w.retryOrDLQ(ctx, message, err); retryErr != nil {
				return errors.Join(err, retryErr)
			}
		}
		if err = reader.CommitMessages(ctx, message); err != nil {
			return fmt.Errorf("commit ticket offset: %w", err)
		}
	}
}

func (w *Worker) apply(ctx context.Context, message kafka.Message) error {
	eventID, err := uuid.Parse(header(message.Headers, "event_id"))
	if err != nil {
		return fmt.Errorf("invalid event_id: %w", err)
	}
	eventType := header(message.Headers, "event_type")
	if eventType == "" {
		return errors.New("ticket event misses event_type")
	}
	// Routing only owns the lifecycle reaction for terminal ticket events.
	// Category, create, update and assignment events share the same topic and
	// must be acknowledged instead of being treated as poison messages.
	if eventType != "ticket.canceled" && eventType != "ticket.completed" {
		return nil
	}
	var event routeEvent
	if err = json.Unmarshal(message.Value, &event); err != nil {
		return fmt.Errorf("decode ticket event: %w", err)
	}
	ticketIDValue := event.TicketID
	if ticketIDValue == "" {
		ticketIDValue = event.ID
	}
	ticketID, err := uuid.Parse(ticketIDValue)
	if err != nil {
		return fmt.Errorf("invalid ticket_id: %w", err)
	}
	target := ""
	switch eventType {
	case "ticket.canceled":
		target = "CANCELLED"
	case "ticket.completed":
		target = "COMPLETED"
	}

	tx, err := w.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var inserted uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO ticket_inbox_events(event_id,event_type,topic,partition_id,message_offset,payload)
		VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT DO NOTHING RETURNING event_id`,
		eventID, eventType, message.Topic, message.Partition, message.Offset, message.Value).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	if target != "" {
		var routeID uuid.UUID
		err = tx.QueryRow(ctx, `UPDATE routes SET status=$2,updated_at=now()
			WHERE ticket_id=$1 AND status IN ('PLANNED','ACTIVE') RETURNING id`, ticketID, target).Scan(&routeID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO outbox_events(aggregate_id,event_type,payload)
				SELECT id,'routing.route.status_changed.v1',to_jsonb(routes) FROM routes WHERE id=$1`, routeID)
			if err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func (w *Worker) retryOrDLQ(ctx context.Context, message kafka.Message, processErr error) error {
	attempt := retries(message.Headers) + 1
	topic := w.topic + ".retry"
	if attempt > 5 {
		topic = w.topic + ".dlq"
	}
	return w.writer.WriteMessages(ctx, kafka.Message{Topic: topic, Key: message.Key, Value: message.Value, Headers: withHeaders(message.Headers, attempt, processErr), Time: time.Now().UTC()})
}

func header(headers []kafka.Header, key string) string {
	for _, value := range headers {
		if strings.EqualFold(value.Key, key) {
			return string(value.Value)
		}
	}
	return ""
}

func retries(headers []kafka.Header) int {
	value, _ := strconv.Atoi(header(headers, retryHeader))
	return max(value, 0)
}

func withHeaders(headers []kafka.Header, attempt int, processErr error) []kafka.Header {
	result := make([]kafka.Header, 0, len(headers)+2)
	for _, value := range headers {
		if !strings.EqualFold(value.Key, retryHeader) && !strings.EqualFold(value.Key, "x-error") {
			result = append(result, value)
		}
	}
	message := processErr.Error()
	if len(message) > 1000 {
		message = message[:1000]
	}
	return append(result, kafka.Header{Key: retryHeader, Value: []byte(strconv.Itoa(attempt))}, kafka.Header{Key: "x-error", Value: []byte(message)})
}

func clean(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}
