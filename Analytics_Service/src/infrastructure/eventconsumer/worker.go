package eventconsumer

import (
	"analytics/pkg/telemetry"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"analytics/models"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

type Worker struct {
	reader *kafka.Reader
	s      EventConsumer
	log    *zap.Logger
	topic  string
	group  string
}

type EventConsumer interface {
	Consume(context.Context, models.Event) error
}

func New(brokers []string, topic, groupID string, service EventConsumer, logger *zap.Logger) *Worker {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Topic:          topic,
		GroupID:        groupID,
		CommitInterval: 0,
		MinBytes:       1,
		MaxBytes:       10e6,
	})

	return &Worker{
		reader: reader,
		s:      service,
		log:    logger,
		topic:  topic,
		group:  groupID,
	}
}

func (w *Worker) Run(c context.Context) error {
	for {
		m, e := w.reader.FetchMessage(c)
		if e != nil {
			if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
				return nil
			}
			w.log.Warn("fetch event failed; retrying", zap.String("topic", w.topic), zap.Error(e))
			select {
			case <-c.Done():
				return nil
			case <-time.After(time.Second):
				continue
			}
		}
		messageCtx, span := telemetry.StartKafkaConsumer(c, m, w.group)
		p := map[string]any{}
		if e = json.Unmarshal(m.Value, &p); e != nil {
			telemetry.End(span, e)
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
		if e = w.s.Consume(messageCtx, models.Event{ID: id, Type: kind, Topic: w.topic, Payload: p, Timestamp: m.Time}); e != nil {
			telemetry.End(span, e)
			w.log.Error("event processing failed", zap.String("topic", w.topic), zap.Error(e))
			continue
		}
		if e = w.reader.CommitMessages(c, m); e != nil {
			telemetry.End(span, e)
			return e
		}
		telemetry.End(span, nil)
	}
}

func (w *Worker) Close() error {
	return w.reader.Close()
}

func first(v ...string) string {
	for _, x := range v {
		if x != "" {
			return x
		}
	}
	return ""
}

func str(payload map[string]any, key string) string {
	value, _ := payload[key].(string)
	return value
}
