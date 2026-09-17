package eventconsumer

import (
	"audit/pkg/telemetry"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"audit/models"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

type Worker struct {
	reader  *kafka.Reader
	service EventConsumer
	logger  *zap.Logger
	topic   string
	group   string
	writer  *kafka.Writer
}

type EventConsumer interface {
	Consume(context.Context, models.Event) error
}

func New(brokers []string, topic, group string, service EventConsumer, logger *zap.Logger) *Worker {
	reader := kafka.NewReader(kafka.ReaderConfig{Brokers: brokers, Topic: topic, GroupID: group, CommitInterval: 0, MinBytes: 1, MaxBytes: 10e6})
	return &Worker{
		reader:  reader,
		service: service,
		logger:  logger,
		topic:   topic,
		group:   group,
		writer:  &kafka.Writer{Addr: kafka.TCP(brokers...), RequiredAcks: kafka.RequireAll},
	}
}

func (w *Worker) Run(ctx context.Context) error {
	for {
		message, err := w.reader.FetchMessage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			w.logger.Warn("fetch event failed; retrying", zap.String("topic", w.topic), zap.Error(err))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
				continue
			}
		}
		messageCtx, span := telemetry.StartKafkaConsumer(ctx, message, w.group)
		payload := map[string]any{}
		if err = json.Unmarshal(message.Value, &payload); err != nil {
			telemetry.End(span, err)
			w.logger.Error("invalid event", zap.String("topic", w.topic), zap.Error(err))
			if err = w.publishDLQ(messageCtx, message, err); err != nil {
				return err
			}
			if err = w.reader.CommitMessages(ctx, message); err != nil {
				return err
			}
			continue
		}
		headers := make(map[string]string, len(message.Headers))
		for _, header := range message.Headers {
			headers[header.Key] = string(header.Value)
		}
		id := first(headers["event_id"], value(payload, "event_id"))
		if id == "" {
			id = fmt.Sprintf("%s:%d:%d", w.topic, message.Partition, message.Offset)
		}
		action := first(headers["event_type"], value(payload, "event_type"), value(payload, "type"))
		if action == "" {
			action = "unknown." + strconv.FormatInt(message.Offset, 10)
		}
		event := models.Event{ID: id, Type: action, Topic: w.topic, Payload: payload, Headers: headers, Timestamp: message.Time}
		err = retryCurrent(messageCtx, func() error { return w.service.Consume(messageCtx, event) }, func(attempt int, retryErr error) {
			w.logger.Error("event processing failed; retrying current offset", zap.String("topic", w.topic), zap.Int("attempt", attempt), zap.Int64("offset", message.Offset), zap.Error(retryErr))
		})
		if err != nil {
			telemetry.End(span, err)
			return nil
		}
		if err = w.reader.CommitMessages(ctx, message); err != nil {
			telemetry.End(span, err)
			return err
		}
		telemetry.End(span, nil)
	}
}

func (w *Worker) Close() error {
	return errors.Join(w.reader.Close(), w.writer.Close())
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
func first(values ...string) string {
	for _, item := range values {
		if item != "" {
			return item
		}
	}
	return ""
}
func value(payload map[string]any, key string) string {
	value, _ := payload[key].(string)
	return value
}
