package ticketconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sla/models"
	"sla/pkg/telemetry"
	"sla/src/core/service"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

type Worker struct {
	reader *kafka.Reader
	s      *service.Service
	log    *zap.Logger
	group  string
	topic  string
	writer *kafka.Writer
}

func New(brokers []string, topic, group string, s *service.Service, l *zap.Logger) *Worker {
	return &Worker{
		reader: kafka.NewReader(kafka.ReaderConfig{
			Brokers:        brokers,
			Topic:          topic,
			GroupID:        group,
			MinBytes:       1,
			MaxBytes:       10e6,
			CommitInterval: 0,
		}),
		s:     s,
		log:   l,
		group: group,
		topic: topic,
		writer: &kafka.Writer{
			Addr:         kafka.TCP(brokers...),
			RequiredAcks: kafka.RequireAll,
		},
	}
}

func (w *Worker) Close() error {
	return errors.Join(w.reader.Close(), w.writer.Close())
}

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
			if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
				return nil
			}
			w.log.Warn("fetch ticket event failed; retrying", zap.Error(e))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
				continue
			}
		}
		messageCtx, span := telemetry.StartKafkaConsumer(ctx, m, w.group)
		var p payload
		if e = json.Unmarshal(m.Value, &p); e != nil {
			telemetry.End(span, e)
			w.log.Error("invalid ticket event", zap.Error(e))
			if e = w.publishDLQ(messageCtx, m, e); e != nil {
				return e
			}
			if e = w.reader.CommitMessages(ctx, m); e != nil {
				return e
			}
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
			identifierErr := fmt.Errorf("invalid ticket event identifiers: %w", errors.Join(e1, e2, e3))
			telemetry.End(span, identifierErr)
			w.log.Error("invalid ticket event identifiers")
			if e = w.publishDLQ(messageCtx, m, identifierErr); e != nil {
				return e
			}
			if e = w.reader.CommitMessages(ctx, m); e != nil {
				return e
			}
			continue
		}

		event := models.TicketEvent{
			EventID:      p.EventID,
			EventType:    p.EventType,
			TicketID:     tid,
			DepartmentID: did,
			CategoryID:   cid,
			Priority:     models.Priority(strings.ToUpper(p.Priority)),
			Status:       p.Status,
			CreatedAt:    p.CreatedAt,
			UpdatedAt:    p.UpdatedAt,
		}
		e = retryCurrent(messageCtx, func() error { return w.s.Consume(messageCtx, event) }, func(attempt int, retryErr error) {
			w.log.Error("ticket event processing failed; retrying current offset", zap.Int("attempt", attempt), zap.Int64("offset", m.Offset), zap.Error(retryErr))
		})
		if e != nil {
			telemetry.End(span, e)
			return nil
		}

		if e = w.reader.CommitMessages(ctx, m); e != nil {
			telemetry.End(span, e)
			return e
		}

		telemetry.End(span, nil)
	}
}

func (w *Worker) publishDLQ(ctx context.Context, message kafka.Message, processErr error) error {
	return telemetry.WriteKafka(ctx, w.writer, dlqMessage(w.topic, message, processErr))
}

func dlqMessage(topic string, message kafka.Message, processErr error) kafka.Message {
	errorText := processErr.Error()
	if len(errorText) > 1000 {
		errorText = errorText[:1000]
	}
	headers := append([]kafka.Header{}, message.Headers...)
	headers = append(headers,
		kafka.Header{Key: "x-error", Value: []byte(errorText)},
		kafka.Header{Key: "x-original-topic", Value: []byte(message.Topic)},
		kafka.Header{Key: "x-original-partition", Value: []byte(strconv.Itoa(message.Partition))},
		kafka.Header{Key: "x-original-offset", Value: []byte(strconv.FormatInt(message.Offset, 10))},
	)
	return kafka.Message{Topic: topic + ".dlq", Key: message.Key, Value: message.Value, Headers: headers, Time: time.Now().UTC()}
}

func retryCurrent(ctx context.Context, process func() error, onError func(int, error)) error {
	for attempt := 1; ; attempt++ {
		if err := process(); err == nil {
			return nil
		} else {
			onError(attempt, err)
		}
		delay := time.Duration(1<<min(attempt-1, 5)) * time.Second
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func header(m kafka.Message, key string) string {
	for _, h := range m.Headers {
		if strings.EqualFold(h.Key, key) {
			return string(h.Value)
		}
	}
	return ""
}
