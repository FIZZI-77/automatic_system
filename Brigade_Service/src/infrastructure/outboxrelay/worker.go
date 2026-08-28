package outboxrelay

import (
	"brigade/pkg/telemetry"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	defaultBatchSize    = 50
	defaultPollInterval = time.Second
	defaultMaxAttempts  = 10
	defaultLockTimeout  = 5 * time.Minute
	defaultWorkerCount  = 4
)

type Config struct {
	Brokers      []string
	Topic        string
	BatchSize    int
	PollInterval time.Duration
	MaxAttempts  int
	LockTimeout  time.Duration
	WorkerCount  int
}

type Worker struct {
	db     *pgxpool.Pool
	writer *kafka.Writer
	cfg    Config
	logger *zap.Logger
}

type event struct {
	ID            uuid.UUID
	AggregateType string
	AggregateID   uuid.UUID
	EventType     string
	Payload       json.RawMessage
	Attempts      int
}

func New(db *pgxpool.Pool, cfg Config, logger *zap.Logger) (*Worker, error) {
	cfg.Brokers = cleanBrokers(cfg.Brokers)
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("outbox relay: at least one Kafka broker is required")
	}
	if strings.TrimSpace(cfg.Topic) == "" {
		return nil, errors.New("outbox relay: topic is required")
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.LockTimeout <= 0 {
		cfg.LockTimeout = defaultLockTimeout
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = defaultWorkerCount
	}

	writer := &kafka.Writer{
		Addr:         kafka.TCP(cfg.Brokers...),
		Topic:        cfg.Topic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireAll,
		Async:        false,
	}
	return &Worker{db: db, writer: writer, cfg: cfg, logger: logger}, nil
}

func (w *Worker) Close() error { return w.writer.Close() }

func (w *Worker) Run(ctx context.Context) error {
	w.logger.Info("outbox relay started", zap.String("topic", w.cfg.Topic), zap.Int("workers", w.cfg.WorkerCount))
	var workers sync.WaitGroup
	workers.Add(w.cfg.WorkerCount)
	for workerID := range w.cfg.WorkerCount {
		go func() {
			defer workers.Done()
			w.runWorker(ctx, workerID)
		}()
	}
	workers.Wait()
	return nil
}

func (w *Worker) runWorker(ctx context.Context, workerID int) {
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()

	for {
		if err := w.processBatch(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Error("outbox relay batch failed", zap.Int("worker_id", workerID), zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Worker) processBatch(ctx context.Context) (err error) {
	var span trace.Span
	defer func() {
		if span != nil {
			telemetry.End(span, err)
		}
	}()
	for range w.cfg.BatchSize {
		item, err := w.claim(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if span == nil {
			ctx, span = telemetry.Tracer("brigade/outbox").Start(ctx, "Outbox.PublishBatch")
		}
		err = telemetry.WriteKafka(ctx, w.writer, kafka.Message{
			Key:   []byte(item.AggregateID.String()),
			Value: item.Payload,
			Headers: []kafka.Header{
				{Key: "event_id", Value: []byte(item.ID.String())},
				{Key: "event_type", Value: []byte(item.EventType)},
				{Key: "aggregate_type", Value: []byte(item.AggregateType)},
			},
			Time: time.Now().UTC(),
		})
		if err != nil {
			if markErr := w.markFailed(ctx, item, err); markErr != nil {
				return errors.Join(err, markErr)
			}
			continue
		}
		if err = w.markSent(ctx, item.ID); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) claim(ctx context.Context) (event, error) {
	tx, err := w.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return event{}, fmt.Errorf("begin claim: %w", err)
	}
	defer tx.Rollback(ctx)

	var item event
	err = tx.QueryRow(ctx, `
		SELECT id, aggregate_type, aggregate_id, event_type, payload, attempts
		FROM outbox_events
		WHERE (
			(status IN ('PENDING', 'FAILED') AND next_attempt_at <= now())
			OR (status = 'PROCESSING' AND locked_at < now() - make_interval(secs => $1))
		)
		AND attempts < $2
		ORDER BY created_at
		FOR UPDATE SKIP LOCKED
		LIMIT 1`,
		w.cfg.LockTimeout.Seconds(), w.cfg.MaxAttempts,
	).Scan(&item.ID, &item.AggregateType, &item.AggregateID, &item.EventType, &item.Payload, &item.Attempts)
	if err != nil {
		return event{}, err
	}
	_, err = tx.Exec(ctx, `
		UPDATE outbox_events
		SET status = 'PROCESSING', locked_at = now(), attempts = attempts + 1, last_error = NULL
		WHERE id = $1`, item.ID)
	if err != nil {
		return event{}, fmt.Errorf("mark processing: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return event{}, fmt.Errorf("commit claim: %w", err)
	}
	item.Attempts++
	return item, nil
}

func (w *Worker) markSent(ctx context.Context, id uuid.UUID) error {
	_, err := w.db.Exec(ctx, `
		UPDATE outbox_events
		SET status = 'SENT', sent_at = now(), locked_at = NULL, last_error = NULL
		WHERE id = $1`, id)
	return err
}

func (w *Worker) markFailed(ctx context.Context, item event, publishErr error) error {
	status := "FAILED"
	if item.Attempts >= w.cfg.MaxAttempts {
		status = "FAILED"
	}
	delay := time.Duration(math.Pow(2, float64(min(item.Attempts-1, 8)))) * time.Second
	_, err := w.db.Exec(ctx, `
		UPDATE outbox_events
		SET status = $2, last_error = $3, next_attempt_at = now() + make_interval(secs => $4), locked_at = NULL
		WHERE id = $1`, item.ID, status, truncate(publishErr.Error(), 2000), delay.Seconds())
	return err
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

func truncate(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}
	return value[:maxLen]
}
