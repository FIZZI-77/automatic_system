package outboxrelay

import (
	"context"
	"errors"
	"sla/pkg/telemetry"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Worker struct {
	db     *pgxpool.Pool
	writer *kafka.Writer
	log    *zap.Logger
}

func New(db *pgxpool.Pool, brokers []string, topic string, l *zap.Logger) *Worker {
	writer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireAll,
	}

	return &Worker{
		db:     db,
		writer: writer,
		log:    l,
	}
}

func (w *Worker) Close() error {
	return w.writer.Close()
}

func (w *Worker) Run(ctx context.Context) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		if e := w.batch(ctx); e != nil && !errors.Is(e, context.Canceled) {
			w.log.Error("outbox batch failed", zap.Error(e))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

func (w *Worker) batch(ctx context.Context) (err error) {
	var span trace.Span
	defer func() {
		if span != nil {
			telemetry.End(span, err)
		}
	}()
	for range 50 {
		tx, e := w.db.Begin(ctx)
		if e != nil {
			return e
		}
		var id, aggregate uuid.UUID
		var kind string
		var payload []byte
		e = tx.QueryRow(
			ctx,
			`SELECT id,aggregate_id,event_type,payload FROM outbox_events WHERE (status IN('PENDING','FAILED') AND next_attempt_at<=now() OR status='PROCESSING' AND locked_at < now()-interval '5 minutes') ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`,
		).Scan(&id, &aggregate, &kind, &payload)
		if errors.Is(e, pgx.ErrNoRows) {
			tx.Rollback(ctx)
			return nil
		}
		if e != nil {
			tx.Rollback(ctx)
			return e
		}
		if span == nil {
			ctx, span = telemetry.Tracer("sla/outbox").Start(ctx, "Outbox.PublishBatch")
		}
		_, e = tx.Exec(ctx, `UPDATE outbox_events SET status='PROCESSING',locked_at=now(),attempts=attempts+1 WHERE id=$1`, id)
		if e == nil {
			e = tx.Commit(ctx)
		}
		if e != nil {
			return e
		}
		e = telemetry.WriteKafka(ctx, w.writer, kafka.Message{
			Key:   []byte(aggregate.String()),
			Value: payload,
			Headers: []kafka.Header{
				{Key: "event_id", Value: []byte(id.String())},
				{Key: "event_type", Value: []byte(kind)},
			},
		})
		if e != nil {
			_, _ = w.db.Exec(ctx, `UPDATE outbox_events SET status='FAILED',last_error=$2,next_attempt_at=now()+interval '5 seconds',locked_at=NULL WHERE id=$1`, id, e.Error())
			continue
		}
		_, e = w.db.Exec(ctx, `UPDATE outbox_events SET status='SENT',sent_at=now(),locked_at=NULL WHERE id=$1`, id)
		if e != nil {
			return e
		}
	}
	return nil
}
