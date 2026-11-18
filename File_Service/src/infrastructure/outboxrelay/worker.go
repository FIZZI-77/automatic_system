package outboxrelay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

type messageWriter interface {
	WriteMessages(context.Context, ...kafka.Message) error
}

// Worker publishes committed outbox rows with at-least-once delivery.
type Worker struct {
	db     *pgxpool.Pool
	writer messageWriter
	logger *zap.Logger
}

// New uses a synchronous writer; a row is acknowledged only after Kafka confirms it.
func New(db *pgxpool.Pool, writer messageWriter, logger *zap.Logger) *Worker {
	return &Worker{db: db, writer: writer, logger: logger}
}

// Run retries failures until cancellation without discarding events during outages.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		for range 50 {
			err := w.publishNext(ctx)
			if errors.Is(err, pgx.ErrNoRows) {
				break
			}
			if err != nil {
				if ctx.Err() == nil {
					w.logger.Error("outbox publish failed; retrying", zap.Error(err))
				}
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Worker) publishNext(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin outbox publish: %w", err)
	}
	defer func() {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer rollbackCancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	var sequence int64
	var id, aggregateID, kind string
	var payload []byte
	var createdAt time.Time
	// The row lock remains held through the bounded Kafka write. A crashed worker
	// releases it automatically; other replicas skip locked rows.
	err = tx.QueryRow(ctx, `SELECT sequence,id::text,aggregate_id::text,event_type,
        payload || jsonb_build_object('event_id',id,'event_type',event_type,
            'event_version',1,'occurred_at',created_at),created_at
        FROM outbox_events WHERE sent_at IS NULL AND next_attempt_at<=now()
        ORDER BY sequence FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(
		&sequence, &id, &aggregateID, &kind, &payload, &createdAt)
	if err != nil {
		return err
	}
	publishErr := w.writer.WriteMessages(ctx, kafka.Message{
		Key: []byte(aggregateID), Value: payload, Time: createdAt,
		Headers: []kafka.Header{
			{Key: "event_id", Value: []byte(id)},
			{Key: "event_type", Value: []byte(kind)},
			{Key: "event_version", Value: []byte("1")},
		},
	})
	if publishErr != nil {
		_, err = tx.Exec(ctx, `UPDATE outbox_events SET attempts=attempts+1,
            last_error=$2,next_attempt_at=now()+make_interval(secs=>LEAST(300,power(2,LEAST(attempts,8)))::int)
            WHERE sequence=$1`, sequence, publishErr.Error())
	} else {
		_, err = tx.Exec(ctx, `UPDATE outbox_events SET sent_at=now(),attempts=attempts+1,last_error=NULL WHERE sequence=$1`, sequence)
	}
	if err != nil {
		return errors.Join(publishErr, err)
	}
	return errors.Join(publishErr, tx.Commit(ctx))
}
