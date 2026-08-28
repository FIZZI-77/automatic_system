package outboxrelay

import (
	"asset/pkg/telemetry"
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Worker struct {
	db *pgxpool.Pool
	w  *kafka.Writer
	l  *zap.Logger
}

func New(db *pgxpool.Pool, brokers []string, topic string, logger *zap.Logger) *Worker {
	writer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireAll,
	}

	return &Worker{
		db: db,
		w:  writer,
		l:  logger,
	}
}

func (w *Worker) Close() error {
	return w.w.Close()
}

func (w *Worker) Run(c context.Context) error {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		if e := w.batch(c); e != nil && !errors.Is(e, context.Canceled) {
			w.l.Error("outbox failed", zap.Error(e))
		}
		select {
		case <-c.Done():
			return nil
		case <-t.C:
		}
	}
}

func (w *Worker) batch(c context.Context) (err error) {
	var span trace.Span
	defer func() {
		if span != nil {
			telemetry.End(span, err)
		}
	}()

	for range 50 {
		tx, e := w.db.Begin(c)
		if e != nil {
			return e
		}
		var id, a uuid.UUID
		var typ string
		var p []byte
		e = tx.QueryRow(
			c,
			`SELECT id,aggregate_id,event_type,payload FROM outbox_events WHERE (status IN('PENDING','FAILED') AND next_attempt_at<=now() OR status='PROCESSING' AND locked_at < now()-interval '5 minutes') ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`,
		).Scan(&id, &a, &typ, &p)
		if errors.Is(e, pgx.ErrNoRows) {
			tx.Rollback(c)
			return nil
		}
		if e != nil {
			tx.Rollback(c)
			return e
		}
		if span == nil {
			c, span = telemetry.Tracer("asset/outbox").Start(c, "Outbox.PublishBatch")
		}
		_, e = tx.Exec(c, "UPDATE outbox_events SET status='PROCESSING',attempts=attempts+1 WHERE id=$1", id)
		if e == nil {
			e = tx.Commit(c)
		}
		if e == nil {
			e = telemetry.WriteKafka(c, w.w, kafka.Message{
				Key:   []byte(a.String()),
				Value: p,
			})
		}
		if e != nil {
			if _, updateErr := w.db.Exec(
				c,
				"UPDATE outbox_events SET status='FAILED',last_error=$2,next_attempt_at=now()+interval '5 sec',locked_at=NULL WHERE id=$1",
				id,
				e.Error(),
			); updateErr != nil {
				return updateErr
			}
			continue
		}
		_, e = w.db.Exec(c, "UPDATE outbox_events SET status='SENT',sent_at=now()WHERE id=$1", id)
		if e != nil {
			return e
		}
	}
	return nil
}
