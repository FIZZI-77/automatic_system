package profileconsumer

import (
	"brigade/pkg/telemetry"
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

const (
	retryHeader = "x-retry-count"
	maxRetries  = 5
)

type Config struct {
	Brokers      []string
	Topic        string
	GroupID      string
	Workers      int
	RetryWorkers int
}

type Worker struct {
	db           *pgxpool.Pool
	readers      []*kafka.Reader
	retryReaders []*kafka.Reader
	writer       *kafka.Writer
	topic        string
	logger       *zap.Logger
	closeOnce    sync.Once
}

type envelope struct {
	EventID      uuid.UUID       `json:"event_id"`
	EventType    string          `json:"event_type"`
	EventVersion int             `json:"event_version"`
	AggregateID  uuid.UUID       `json:"aggregate_id"`
	OccurredAt   time.Time       `json:"occurred_at"`
	Payload      json.RawMessage `json:"payload"`
}

type skillGrant struct {
	ID               uuid.UUID  `json:"id"`
	WorkProfileID    uuid.UUID  `json:"work_profile_id"`
	SkillID          uuid.UUID  `json:"skill_id"`
	ProficiencyLevel *string    `json:"proficiency_level"`
	ValidUntil       *time.Time `json:"valid_until"`
	Active           bool       `json:"active"`
}

type skillGrantPayload struct {
	SkillGrant *skillGrant `json:"skill_grant"`
}

type statusPayload struct {
	WorkProfileID uuid.UUID `json:"work_profile_id"`
	ToStatus      string    `json:"to_status"`
	Status        string    `json:"status"`
}

func New(db *pgxpool.Pool, cfg Config, logger *zap.Logger) (*Worker, error) {
	cfg.Brokers = cleanBrokers(cfg.Brokers)
	if len(cfg.Brokers) == 0 || strings.TrimSpace(cfg.Topic) == "" || strings.TrimSpace(cfg.GroupID) == "" {
		return nil, errors.New("profile consumer: brokers, topic and group id are required")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.RetryWorkers <= 0 {
		cfg.RetryWorkers = 2
	}
	newReader := func(topic, groupID string) *kafka.Reader {
		return kafka.NewReader(kafka.ReaderConfig{
			Brokers: cfg.Brokers, Topic: topic, GroupID: groupID,
			MinBytes: 1, MaxBytes: 10e6, CommitInterval: 0,
		})
	}
	worker := &Worker{
		db:           db,
		readers:      make([]*kafka.Reader, 0, cfg.Workers),
		retryReaders: make([]*kafka.Reader, 0, cfg.RetryWorkers),
		writer: &kafka.Writer{
			Addr: kafka.TCP(cfg.Brokers...), RequiredAcks: kafka.RequireAll,
		},
		topic: cfg.Topic, logger: logger,
	}
	for range cfg.Workers {
		worker.readers = append(worker.readers, newReader(cfg.Topic, cfg.GroupID))
	}
	for range cfg.RetryWorkers {
		worker.retryReaders = append(worker.retryReaders, newReader(cfg.Topic+".retry", cfg.GroupID+".retry"))
	}
	return worker, nil
}

func (w *Worker) Run(ctx context.Context) error {
	w.logger.Info("profile inbox consumer started",
		zap.String("topic", w.topic),
		zap.Int("workers", len(w.readers)),
		zap.Int("retry_workers", len(w.retryReaders)),
	)
	errs := make(chan error, len(w.readers)+len(w.retryReaders))
	for _, reader := range w.readers {
		go func(r *kafka.Reader) { errs <- w.consume(ctx, r) }(reader)
	}
	for _, reader := range w.retryReaders {
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
		for _, reader := range append(w.readers, w.retryReaders...) {
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
			return fmt.Errorf("fetch message: %w", err)
		}
		if strings.HasSuffix(message.Topic, ".retry") {
			delay := time.Duration(1<<min(retryCount(message.Headers), maxRetries)) * time.Second
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
		if err = telemetry.TraceKafkaConsumer(ctx, message, "", w.apply); err != nil {
			w.logger.Error("profile event processing failed", zap.Error(err), zap.Int64("offset", message.Offset))
			if retryErr := w.retryOrDLQ(ctx, message, err); retryErr != nil {
				return errors.Join(err, retryErr)
			}
		}
		if err = reader.CommitMessages(ctx, message); err != nil {
			return fmt.Errorf("commit Kafka offset: %w", err)
		}
	}
}

func (w *Worker) apply(ctx context.Context, message kafka.Message) error {
	var event envelope
	if err := json.Unmarshal(message.Value, &event); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if event.EventID == uuid.Nil || event.EventType == "" {
		return errors.New("invalid event envelope")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = message.Time.UTC()
	}

	tx, err := w.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var alreadyProcessed bool
	err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM inbox_events WHERE event_id = $1)`, event.EventID).Scan(&alreadyProcessed)
	if err != nil {
		return err
	}
	if alreadyProcessed {
		return tx.Commit(ctx)
	}

	switch event.EventType {
	case "WorkProfileSkillGrantChanged", "WorkProfileSkillGranted", "WorkProfileSkillRevoked":
		if err = applySkillGrant(ctx, tx, event); err != nil {
			return err
		}
	case "WorkProfileStatusChanged", "WorkProfileDeactivated":
		if err = applyWorkProfileStatus(ctx, tx, event); err != nil {
			return err
		}
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO inbox_events (
			event_id, source_service, topic, partition_id, message_offset,
			event_type, event_version, occurred_at, payload
		) VALUES ($1, 'profile', $2, $3, $4, $5, $6, $7, $8::jsonb)
		ON CONFLICT (event_id) DO NOTHING`,
		event.EventID, message.Topic, message.Partition, message.Offset,
		event.EventType, max(event.EventVersion, 1), event.OccurredAt, message.Value)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func applySkillGrant(ctx context.Context, tx pgx.Tx, event envelope) error {
	var wrapper skillGrantPayload
	var grant skillGrant
	if err := json.Unmarshal(event.Payload, &wrapper); err != nil {
		return fmt.Errorf("decode skill grant payload: %w", err)
	}
	if wrapper.SkillGrant != nil {
		grant = *wrapper.SkillGrant
	} else if err := json.Unmarshal(event.Payload, &grant); err != nil {
		return fmt.Errorf("decode skill grant: %w", err)
	}
	if grant.ID == uuid.Nil || grant.WorkProfileID == uuid.Nil || grant.SkillID == uuid.Nil {
		return errors.New("skill grant event misses required ids")
	}
	if event.EventType == "WorkProfileSkillRevoked" {
		grant.Active = false
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO brigade_member_skills (
			brigade_id, member_id, work_profile_id, skill_id, source_grant_id,
			proficiency_level, valid_until, active, source_occurred_at
		)
		SELECT brigade_id, id, $1, $2, $3, $4, $5, $6, $7
		FROM brigade_members
		WHERE profile_id = $1 AND active = true
		ON CONFLICT (member_id, source_grant_id) DO UPDATE SET
			skill_id = EXCLUDED.skill_id,
			proficiency_level = EXCLUDED.proficiency_level,
			valid_until = EXCLUDED.valid_until,
			active = EXCLUDED.active,
			source_occurred_at = EXCLUDED.source_occurred_at,
			updated_at = now()
		WHERE brigade_member_skills.source_occurred_at <= EXCLUDED.source_occurred_at`,
		grant.WorkProfileID, grant.SkillID, grant.ID, grant.ProficiencyLevel,
		grant.ValidUntil, grant.Active, event.OccurredAt)
	return err
}

func applyWorkProfileStatus(ctx context.Context, tx pgx.Tx, event envelope) error {
	var payload statusPayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return err
	}
	status := payload.ToStatus
	if status == "" {
		status = payload.Status
	}
	if payload.WorkProfileID == uuid.Nil {
		payload.WorkProfileID = event.AggregateID
	}
	if payload.WorkProfileID == uuid.Nil {
		return errors.New("status event misses work_profile_id")
	}
	active := strings.EqualFold(status, "ACTIVE") || strings.EqualFold(status, "ON_SHIFT")
	_, err := tx.Exec(ctx, `
		UPDATE brigade_member_skills
		SET work_profile_active = $2, source_occurred_at = $3, updated_at = now()
		WHERE work_profile_id = $1 AND source_occurred_at <= $3`,
		payload.WorkProfileID, active, event.OccurredAt)
	return err
}

func (w *Worker) retryOrDLQ(ctx context.Context, message kafka.Message, processErr error) error {
	attempt := retryCount(message.Headers) + 1
	target := w.topic + ".retry"
	if attempt > maxRetries {
		target = w.topic + ".dlq"
	}
	headers := upsertHeader(message.Headers, retryHeader, strconv.Itoa(attempt))
	headers = upsertHeader(headers, "x-error", truncate(processErr.Error(), 1000))
	return telemetry.WriteKafka(ctx, w.writer, kafka.Message{
		Topic: target, Key: message.Key, Value: message.Value, Headers: headers, Time: time.Now().UTC(),
	})
}

func retryCount(headers []kafka.Header) int {
	for _, header := range headers {
		if strings.EqualFold(header.Key, retryHeader) {
			value, err := strconv.Atoi(string(header.Value))
			if err != nil || value < 0 {
				return 0
			}
			return value
		}
	}
	return 0
}

func cleanBrokers(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func upsertHeader(headers []kafka.Header, key, value string) []kafka.Header {
	result := make([]kafka.Header, 0, len(headers)+1)
	for _, header := range headers {
		if !strings.EqualFold(header.Key, key) {
			result = append(result, header)
		}
	}
	return append(result, kafka.Header{Key: key, Value: []byte(value)})
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
