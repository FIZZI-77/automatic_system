package eventconsumer

import (
	"audit/pkg/telemetry"
	"context"
	"encoding/json"
	"fmt"
	"strconv"

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
	}
}

func (w *Worker) Run(ctx context.Context) error {
	for {
		message, err := w.reader.FetchMessage(ctx)
		if err != nil {
			return err
		}
		messageCtx, span := telemetry.StartKafkaConsumer(ctx, message, w.group)
		payload := map[string]any{}
		if err = json.Unmarshal(message.Value, &payload); err != nil {
			telemetry.End(span, err)
			w.logger.Error("invalid event", zap.String("topic", w.topic), zap.Error(err))
			_ = w.reader.CommitMessages(ctx, message)
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
		err = w.service.Consume(messageCtx, models.Event{ID: id, Type: action, Topic: w.topic, Payload: payload, Headers: headers, Timestamp: message.Time})
		if err != nil {
			telemetry.End(span, err)
			w.logger.Error("event processing failed", zap.String("topic", w.topic), zap.Error(err))
			continue
		}
		if err = w.reader.CommitMessages(ctx, message); err != nil {
			telemetry.End(span, err)
			return err
		}
		telemetry.End(span, nil)
	}
}

func (w *Worker) Close() error {
	return w.reader.Close()
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
