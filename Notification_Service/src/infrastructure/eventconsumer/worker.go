package eventconsumer

import (
	"context"
	"encoding/json"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
	"notification/models"
	"notification/src/core/service"
)

type Worker struct {
	reader *kafka.Reader
	s      *service.Service
	log    *zap.Logger
	topic  string
}

func New(b []string, topic, group string, s *service.Service, l *zap.Logger) *Worker {
	return &Worker{reader: kafka.NewReader(kafka.ReaderConfig{Brokers: b, Topic: topic, GroupID: group, CommitInterval: 0, MinBytes: 1, MaxBytes: 10e6}), s: s, log: l, topic: topic}
}
func (w *Worker) Close() error { return w.reader.Close() }
func (w *Worker) Run(ctx context.Context) error {
	for {
		m, e := w.reader.FetchMessage(ctx)
		if e != nil {
			return e
		}
		payload := map[string]any{}
		if e = json.Unmarshal(m.Value, &payload); e != nil {
			w.log.Error("invalid event", zap.String("topic", w.topic), zap.Error(e))
			_ = w.reader.CommitMessages(ctx, m)
			continue
		}
		id := header(m, "event_id")
		kind := header(m, "event_type")
		if v, ok := payload["event_id"].(string); ok && id == "" {
			id = v
		}
		if v, ok := payload["event_type"].(string); ok && kind == "" {
			kind = v
		}
		if id == "" {
			id = w.topic + ":" + string(m.Key) + ":" + string(rune(m.Partition)) + ":" + string(rune(m.Offset))
		}
		if kind == "" {
			_ = w.reader.CommitMessages(ctx, m)
			continue
		}
		e = w.s.Consume(ctx, models.Event{ID: id, Type: kind, Topic: w.topic, Payload: payload})
		if e != nil {
			w.log.Error("event processing failed", zap.String("topic", w.topic), zap.Error(e))
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
