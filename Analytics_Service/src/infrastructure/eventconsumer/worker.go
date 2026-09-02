package eventconsumer

import (
	"analytics/pkg/telemetry"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"analytics/models"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

type Worker struct {
	reader *kafka.Reader
	dlq    *kafka.Writer
	s      EventConsumer
	log    *zap.Logger
	topic  string
	group  string
}

const maxProcessingAttempts = 5

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
		dlq: &kafka.Writer{
			Addr:         kafka.TCP(brokers...),
			Topic:        topic + ".dlq",
			RequiredAcks: kafka.RequireAll,
		},
		s:     service,
		log:   logger,
		topic: topic,
		group: groupID,
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
		startedAt := time.Now()
		p := map[string]any{}
		if e = json.Unmarshal(m.Value, &p); e != nil {
			decodeErr := e
			telemetry.RecordConsumerResult(messageCtx, w.topic, time.Since(startedAt), w.reader.Stats().Lag, e)
			w.log.Error("invalid event; publishing to DLQ", zap.Error(e))
			if dlqErr := w.publishDLQ(messageCtx, m, decodeErr, 1); dlqErr != nil {
				telemetry.End(span, errors.Join(decodeErr, dlqErr))
				return fmt.Errorf("publish invalid event to DLQ: %w", dlqErr)
			}
			if e = w.reader.CommitMessages(c, m); e != nil {
				telemetry.End(span, e)
				return fmt.Errorf("commit invalid event after DLQ: %w", e)
			}
			telemetry.End(span, decodeErr)
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
		version := eventVersion(h, p)
		event := models.Event{ID: id, Type: kind, Topic: w.topic, Payload: p, Timestamp: m.Time, Version: version}
		for attempt := 1; attempt <= maxProcessingAttempts; attempt++ {
			e = w.s.Consume(messageCtx, event)
			if e == nil {
				break
			}
			telemetry.RecordConsumerResult(messageCtx, w.topic, time.Since(startedAt), w.reader.Stats().Lag, e)
			w.log.Warn("event processing failed", zap.String("topic", w.topic), zap.Int("attempt", attempt), zap.Error(e))
			if attempt < maxProcessingAttempts {
				select {
				case <-c.Done():
					telemetry.End(span, c.Err())
					return nil
				case <-time.After(processingRetryDelay(attempt)):
				}
			}
		}
		if e != nil {
			if dlqErr := w.publishDLQ(messageCtx, m, e, maxProcessingAttempts); dlqErr != nil {
				telemetry.End(span, errors.Join(e, dlqErr))
				return fmt.Errorf("publish failed event to DLQ: %w", dlqErr)
			}
			w.log.Error("event processing attempts exhausted; published to DLQ", zap.String("topic", w.topic), zap.Error(e))
		}
		processingErr := e
		if e = w.reader.CommitMessages(c, m); e != nil {
			telemetry.RecordConsumerResult(messageCtx, w.topic, time.Since(startedAt), w.reader.Stats().Lag, e)
			telemetry.End(span, e)
			return e
		}
		telemetry.RecordConsumerResult(messageCtx, w.topic, time.Since(startedAt), w.reader.Stats().Lag, processingErr)
		telemetry.End(span, processingErr)
	}
}

func eventVersion(headers map[string]string, payload map[string]any) uint32 {
	for _, value := range []any{headers["event_version"], payload["event_version"], payload["EventVersion"]} {
		switch typed := value.(type) {
		case string:
			parsed, err := strconv.ParseUint(typed, 10, 32)
			if err == nil && parsed > 0 {
				return uint32(parsed)
			}
		case float64:
			if typed > 0 && typed <= float64(^uint32(0)) {
				return uint32(typed)
			}
		case int:
			if typed > 0 {
				return uint32(typed)
			}
		}
	}
	return 1
}

func (w *Worker) Close() error {
	return errors.Join(w.reader.Close(), w.dlq.Close())
}

func (w *Worker) publishDLQ(ctx context.Context, source kafka.Message, processingErr error, attempts int) error {
	return w.dlq.WriteMessages(ctx, deadLetterMessage(w.topic, source, processingErr, attempts))
}

func deadLetterMessage(topic string, source kafka.Message, processingErr error, attempts int) kafka.Message {
	headers := make([]kafka.Header, 0, len(source.Headers)+5)
	headers = append(headers, source.Headers...)
	headers = append(headers,
		kafka.Header{Key: "source_topic", Value: []byte(topic)},
		kafka.Header{Key: "source_partition", Value: []byte(strconv.Itoa(source.Partition))},
		kafka.Header{Key: "source_offset", Value: []byte(strconv.FormatInt(source.Offset, 10))},
		kafka.Header{Key: "processing_attempts", Value: []byte(strconv.Itoa(attempts))},
		kafka.Header{Key: "processing_error", Value: []byte(processingErr.Error())},
	)
	return kafka.Message{Key: source.Key, Value: source.Value, Headers: headers, Time: time.Now().UTC()}
}

func processingRetryDelay(attempt int) time.Duration {
	delay := 100 * time.Millisecond * time.Duration(1<<max(0, attempt-1))
	return min(delay, 2*time.Second)
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
