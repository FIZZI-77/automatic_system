package eventconsumer

import (
	"analytics/models"
	"context"
	"encoding/json"
	"fmt"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

type Worker struct {
	reader *kafka.Reader
	s      EventConsumer
	log    *zap.Logger
	topic  string
}

type EventConsumer interface {
	Consume(context.Context, models.Event) error
}

func New(b []string, t, g string, s EventConsumer, l *zap.Logger) *Worker {
	return &Worker{reader: kafka.NewReader(kafka.ReaderConfig{Brokers: b, Topic: t, GroupID: g, CommitInterval: 0, MinBytes: 1, MaxBytes: 10e6}), s: s, log: l, topic: t}
}
func (w *Worker) Run(c context.Context) error {
	for {
		m, e := w.reader.FetchMessage(c)
		if e != nil {
			return e
		}
		p := map[string]any{}
		if e = json.Unmarshal(m.Value, &p); e != nil {
			w.log.Error("invalid event", zap.Error(e))
			_ = w.reader.CommitMessages(c, m)
			continue
		}
		h := map[string]string{}
		for _, x := range m.Headers {
			h[x.Key] = string(x.Value)
		}
		id := first(h["event_id"], str(p, "event_id"))
		if id == "" {
			id = fmt.Sprintf("%s:%d:%d", w.topic, m.Partition, m.Offset)
		}
		kind := first(h["event_type"], str(p, "event_type"), str(p, "type"))
		if kind == "" {
			kind = "unknown"
		}
		if e = w.s.Consume(c, models.Event{ID: id, Type: kind, Topic: w.topic, Payload: p, Timestamp: m.Time}); e != nil {
			w.log.Error("event processing failed", zap.String("topic", w.topic), zap.Error(e))
			continue
		}
		if e = w.reader.CommitMessages(c, m); e != nil {
			return e
		}
	}
}
func (w *Worker) Close() error { return w.reader.Close() }
func first(v ...string) string {
	for _, x := range v {
		if x != "" {
			return x
		}
	}
	return ""
}
func str(p map[string]any, k string) string { x, _ := p[k].(string); return x }
