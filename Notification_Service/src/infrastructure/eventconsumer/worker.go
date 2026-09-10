package eventconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
	"notification/models"
	"notification/pkg/telemetry"
	"notification/src/core/service"
	"strconv"
	"strings"
	"time"
)

type Worker struct {
	reader *kafka.Reader
	s      *service.Service
	log    *zap.Logger
	topic  string
	group  string
	writer *kafka.Writer
}

func New(b []string, topic, group string, s *service.Service, l *zap.Logger) *Worker {
	return &Worker{
		reader: kafka.NewReader(kafka.ReaderConfig{Brokers: b, Topic: topic, GroupID: group, CommitInterval: 0, MinBytes: 1, MaxBytes: 10e6}),
		s:      s,
		log:    l,
		topic:  topic,
		group:  group,
		writer: &kafka.Writer{Addr: kafka.TCP(b...), RequiredAcks: kafka.RequireAll},
	}
}
func (w *Worker) Close() error { return errors.Join(w.reader.Close(), w.writer.Close()) }
func (w *Worker) Run(ctx context.Context) error {
	for {
		m, e := w.reader.FetchMessage(ctx)
		if e != nil {
			if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
				return nil
			}
			w.log.Warn("fetch event failed; retrying", zap.String("topic", w.topic), zap.Error(e))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
				continue
			}
		}
		messageCtx, span := telemetry.StartKafkaConsumer(ctx, m, w.group)
		payload := map[string]any{}
		if e = json.Unmarshal(m.Value, &payload); e != nil {
			telemetry.End(span, e)
			w.log.Error("invalid event", zap.String("topic", w.topic), zap.Error(e))
			if e = w.publishDLQ(messageCtx, m, e); e != nil {
				return e
			}
			if e = w.reader.CommitMessages(ctx, m); e != nil {
				return e
			}
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
			id = fmt.Sprintf("%s:%d:%d", w.topic, m.Partition, m.Offset)
		}
		if kind == "" {
			missingTypeErr := errors.New("event_type is missing")
			telemetry.End(span, missingTypeErr)
			if e = w.publishDLQ(messageCtx, m, missingTypeErr); e != nil {
				return e
			}
			if e = w.reader.CommitMessages(ctx, m); e != nil {
				return e
			}
			continue
		}
		e = w.s.Consume(messageCtx, models.Event{ID: id, Type: kind, Topic: w.topic, Payload: payload})
		if e != nil {
			telemetry.End(span, e)
			w.log.Error("event processing failed", zap.String("topic", w.topic), zap.Error(e))
			if e = w.publishDLQ(messageCtx, m, e); e != nil {
				return e
			}
		}
		if e = w.reader.CommitMessages(ctx, m); e != nil {
			telemetry.End(span, e)
			return e
		}
		telemetry.End(span, nil)
	}
}

func (w *Worker) publishDLQ(ctx context.Context, message kafka.Message, processErr error) error {
	if processErr == nil {
		return errors.New("cannot publish successful message to dlq")
	}
	errorText := processErr.Error()
	if len(errorText) > 1000 {
		errorText = errorText[:1000]
	}
	headers := make([]kafka.Header, 0, len(message.Headers)+5)
	headers = append(headers, message.Headers...)
	headers = append(headers,
		kafka.Header{Key: "x-error", Value: []byte(errorText)},
		kafka.Header{Key: "x-original-topic", Value: []byte(message.Topic)},
		kafka.Header{Key: "x-original-partition", Value: []byte(strconv.Itoa(message.Partition))},
		kafka.Header{Key: "x-original-offset", Value: []byte(strconv.FormatInt(message.Offset, 10))},
	)
	return telemetry.WriteKafka(ctx, w.writer, kafka.Message{
		Topic:   w.topic + ".dlq",
		Key:     message.Key,
		Value:   message.Value,
		Headers: headers,
		Time:    time.Now().UTC(),
	})
}
func header(m kafka.Message, key string) string {
	for _, h := range m.Headers {
		if strings.EqualFold(h.Key, key) {
			return string(h.Value)
		}
	}
	return ""
}
