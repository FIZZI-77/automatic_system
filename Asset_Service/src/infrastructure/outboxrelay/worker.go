package outboxrelay

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
	"time"
)

type Worker struct {
	db *pgxpool.Pool
	w  *kafka.Writer
	l  *zap.Logger
}

func New(db *pgxpool.Pool, b []string, t string, l *zap.Logger) *Worker {
	return &Worker{db, &kafka.Writer{Addr: kafka.TCP(b...), Topic: t, Balancer: &kafka.Hash{}, RequiredAcks: kafka.RequireAll}, l}
}
func (w *Worker) Close() error { return w.w.Close() }
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
func (w *Worker) batch(c context.Context) error {
	for range 50 {
		tx, e := w.db.Begin(c)
		if e != nil {
			return e
		}
		var id, a uuid.UUID
		var typ string
		var p []byte
		e = tx.QueryRow(c, `SELECT id,aggregate_id,event_type,payload FROM outbox_events WHERE status IN('PENDING','FAILED')AND next_attempt_at<=now()ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id, &a, &typ, &p)
		if errors.Is(e, pgx.ErrNoRows) {
			tx.Rollback(c)
			return nil
		}
		if e != nil {
			return e
		}
		_, e = tx.Exec(c, "UPDATE outbox_events SET status='PROCESSING',attempts=attempts+1 WHERE id=$1", id)
		if e == nil {
			e = tx.Commit(c)
		}
		if e == nil {
			e = w.w.WriteMessages(c, kafka.Message{Key: []byte(a.String()), Value: p})
		}
		if e != nil {
			_, _ = w.db.Exec(c, "UPDATE outbox_events SET status='FAILED',last_error=$2,next_attempt_at=now()+interval '5 sec' WHERE id=$1", id, e.Error())
			continue
		}
		_, e = w.db.Exec(c, "UPDATE outbox_events SET status='SENT',sent_at=now()WHERE id=$1", id)
		if e != nil {
			return e
		}
	}
	return nil
}
