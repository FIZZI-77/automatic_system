package outboxrelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"dispatch/pkg/telemetry"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

const (
	defaultBatchSize    = 50
	defaultPollInterval = time.Second
	defaultMaxAttempts  = 10
	defaultLockTimeout  = 5 * time.Minute
	defaultWorkerCount  = 4
)

var errLeaseLost = errors.New("outbox lease lost")

type Config struct {
	Brokers      []string
	Topic        string
	BatchSize    int
	PollInterval time.Duration
	MaxAttempts  int
	LockTimeout  time.Duration
	WorkerCount  int
	InstanceID   uuid.UUID
}

type Worker struct {
	db     *pgxpool.Pool
	writer *kafka.Writer
	cfg    Config
	logger *zap.Logger
}

type event struct {
	ID          uuid.UUID
	AggregateID uuid.UUID
	EventType   string
	Payload     json.RawMessage
	Attempts    int
	LockOwner   uuid.UUID
}

func New(db *pgxpool.Pool, config Config, logger *zap.Logger) (*Worker, error) {
	config.Brokers = cleanBrokers(config.Brokers)
	if db == nil {
		return nil, errors.New("outbox relay: database is required")
	}
	if len(config.Brokers) == 0 {
		return nil, errors.New("outbox relay: at least one Kafka broker is required")
	}
	if strings.TrimSpace(config.Topic) == "" {
		return nil, errors.New("outbox relay: topic is required")
	}
	if config.BatchSize <= 0 {
		config.BatchSize = defaultBatchSize
	}
	if config.PollInterval <= 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = defaultMaxAttempts
	}
	if config.LockTimeout <= 0 {
		config.LockTimeout = defaultLockTimeout
	}
	if config.WorkerCount <= 0 {
		config.WorkerCount = defaultWorkerCount
	}
	if config.InstanceID == uuid.Nil {
		config.InstanceID = uuid.New()
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	writer := &kafka.Writer{
		Addr:         kafka.TCP(config.Brokers...),
		Topic:        config.Topic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireAll,
		Async:        false,
	}
	return &Worker{db: db, writer: writer, cfg: config, logger: logger}, nil
}

func (w *Worker) Close() error { return w.writer.Close() }

func (w *Worker) Run(ctx context.Context) error {
	w.logger.Info("dispatch outbox relay started", zap.Int("workers", w.cfg.WorkerCount))
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
			w.logger.Error("dispatch outbox batch failed", zap.Int("worker_id", workerID), zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Worker) processBatch(ctx context.Context) error {
	for range w.cfg.BatchSize {
		item, err := w.claim(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		err = telemetry.WriteKafka(ctx, w.writer, kafka.Message{
			Key:   []byte(item.AggregateID.String()),
			Value: item.Payload,
			Headers: []kafka.Header{
				{Key: "event_id", Value: []byte(item.ID.String())},
				{Key: "event_type", Value: []byte(item.EventType)},
				{Key: "event_version", Value: []byte("1")},
				{Key: "producer", Value: []byte("dispatch-service")},
			},
			Time: time.Now().UTC(),
		})
		if err != nil {
			if markErr := w.markFailed(ctx, item, err); markErr != nil {
				return errors.Join(err, markErr)
			}
			continue
		}
		if err = w.markSent(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) claim(ctx context.Context) (event, error) {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return event{}, fmt.Errorf("begin outbox claim: %w", err)
	}
	defer tx.Rollback(ctx)
	var item event
	err = tx.QueryRow(ctx, `SELECT id,aggregate_id,event_type,payload,attempts
		FROM dispatch_outbox_events
		WHERE ((status IN ('PENDING','FAILED') AND next_attempt_at<=now())
			OR (status='PROCESSING' AND locked_at<now()-make_interval(secs=>$1)))
			AND attempts<$2
		ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`,
		w.cfg.LockTimeout.Seconds(), w.cfg.MaxAttempts,
	).Scan(&item.ID, &item.AggregateID, &item.EventType, &item.Payload, &item.Attempts)
	if err != nil {
		return event{}, err
	}
	item.LockOwner = w.cfg.InstanceID
	if _, err = tx.Exec(ctx, `UPDATE dispatch_outbox_events
		SET status='PROCESSING',locked_at=now(),locked_by=$2,attempts=attempts+1,last_error=NULL
		WHERE id=$1`, item.ID, item.LockOwner); err != nil {
		return event{}, fmt.Errorf("mark outbox processing: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return event{}, fmt.Errorf("commit outbox claim: %w", err)
	}
	item.Attempts++
	return item, nil
}

func (w *Worker) markSent(ctx context.Context, item event) error {
	result, err := w.db.Exec(ctx, `UPDATE dispatch_outbox_events
		SET status='SENT',sent_at=now(),locked_at=NULL,locked_by=NULL,last_error=NULL
		WHERE id=$1 AND status='PROCESSING' AND locked_by=$2`, item.ID, item.LockOwner)
	return requireLease(result.RowsAffected(), err)
}

func (w *Worker) markFailed(ctx context.Context, item event, publishErr error) error {
	delay := time.Duration(math.Pow(2, float64(min(item.Attempts-1, 8)))) * time.Second
	result, err := w.db.Exec(ctx, `UPDATE dispatch_outbox_events
		SET status='FAILED',last_error=$2,next_attempt_at=now()+make_interval(secs=>$3),locked_at=NULL,locked_by=NULL
		WHERE id=$1 AND status='PROCESSING' AND locked_by=$4`, item.ID, truncate(publishErr.Error(), 2000), delay.Seconds(), item.LockOwner)
	return requireLease(result.RowsAffected(), err)
}

func requireLease(rowsAffected int64, err error) error {
	if err != nil {
		return err
	}
	if rowsAffected != 1 {
		return errLeaseLost
	}
	return nil
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

func truncate(value string, maxLength int) string {
	if len(value) <= maxLength {
		return value
	}
	return value[:maxLength]
}
