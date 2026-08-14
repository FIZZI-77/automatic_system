package ticketconsumer

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
	"sla/models"
	"sla/src/core/service"
	"strings"
	"time"
)

type Worker struct {
	reader *kafka.Reader
	s      *service.Service
	log    *zap.Logger
}

func New(brokers []string, topic, group string, s *service.Service, l *zap.Logger) *Worker {
	return &Worker{reader: kafka.NewReader(kafka.ReaderConfig{Brokers: brokers, Topic: topic, GroupID: group, MinBytes: 1, MaxBytes: 10e6, CommitInterval: 0}), s: s, log: l}
}
func (w *Worker) Close() error { return w.reader.Close() }

type payload struct {
	EventID      string    `json:"event_id"`
	EventType    string    `json:"event_type"`
	ID           string    `json:"id"`
	TicketID     string    `json:"ticket_id"`
	DepartmentID string    `json:"department_id"`
	CategoryID   string    `json:"category_id"`
	Priority     string    `json:"priority"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (w *Worker) Run(ctx context.Context) error {
	for {
		m, e := w.reader.FetchMessage(ctx)
		if e != nil {
			return e
		}
		var p payload
		if e = json.Unmarshal(m.Value, &p); e != nil {
			w.log.Error("invalid ticket event", zap.Error(e))
			_ = w.reader.CommitMessages(ctx, m)
			continue
		}
		if p.EventID == "" {
			p.EventID = header(m, "event_id")
		}
		if p.EventType == "" {
			p.EventType = header(m, "event_type")
		}
		if p.TicketID == "" {
			p.TicketID = p.ID
		}
		tid, e1 := uuid.Parse(p.TicketID)
		did, e2 := uuid.Parse(p.DepartmentID)
		cid, e3 := uuid.Parse(p.CategoryID)
		if e1 != nil || e2 != nil || e3 != nil {
			w.log.Error("invalid ticket event identifiers")
			_ = w.reader.CommitMessages(ctx, m)
			continue
		}
		e = w.s.Consume(ctx, models.TicketEvent{EventID: p.EventID, EventType: p.EventType, TicketID: tid, DepartmentID: did, CategoryID: cid, Priority: models.Priority(strings.ToUpper(p.Priority)), Status: p.Status, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt})
		if e != nil {
			w.log.Error("ticket event processing failed", zap.Error(e))
			continue
		}
		if e = w.reader.CommitMessages(ctx, m); e != nil {
			return e
		}
	}
}
func header(m kafka.Message, key string) string {
	for _, h := range m.Headers {
		if h.Key == key {
			return string(h.Value)
		}
	}
	return ""
}
