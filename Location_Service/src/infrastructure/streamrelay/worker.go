package streamrelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"location/pkg/telemetry"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

type Config struct {
	Brokers   []string
	Topic     string
	Stream    string
	Group     string
	Consumer  string
	Interval  time.Duration
	BatchSize int64
}

type Worker struct {
	rdb    redis.UniversalClient
	writer *kafka.Writer
	cfg    Config
	log    *zap.Logger
}

type eventPayload struct {
	EventID      string         `json:"event_id"`
	EventVersion int            `json:"event_version"`
	EventType    string         `json:"event_type"`
	OccurredAt   string         `json:"occurred_at"`
	Payload      map[string]any `json:"payload"`
}

func New(rdb redis.UniversalClient, cfg Config, logger *zap.Logger) *Worker {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if strings.TrimSpace(cfg.Topic) == "" {
		cfg.Topic = "locations.events.v1"
	}
	if strings.TrimSpace(cfg.Stream) == "" {
		cfg.Stream = "locations:events"
	}
	if strings.TrimSpace(cfg.Group) == "" {
		cfg.Group = "location-kafka-relay"
	}
	if strings.TrimSpace(cfg.Consumer) == "" {
		cfg.Consumer = "location-service"
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	writer := &kafka.Writer{
		Addr:         kafka.TCP(cfg.Brokers...),
		Topic:        cfg.Topic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireAll,
	}
	return &Worker{rdb: rdb, writer: writer, cfg: cfg, log: logger}
}

func (w *Worker) Close() error { return w.writer.Close() }

func (w *Worker) Run(ctx context.Context) {
	if err := w.ensureGroup(ctx); err != nil {
		w.log.Error("redis stream relay group", zap.Error(err))
		return
	}
	for ctx.Err() == nil {
		processed, err := w.flush(ctx, "0")
		if err == nil && processed == 0 {
			_, err = w.flush(ctx, ">")
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			w.log.Error("redis stream relay", zap.Error(err))
		}
		if !wait(ctx, w.cfg.Interval) {
			return
		}
	}
}

func (w *Worker) ensureGroup(ctx context.Context) error {
	err := w.rdb.XGroupCreateMkStream(ctx, w.cfg.Stream, w.cfg.Group, "0").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		return err
	}
	return nil
}

func (w *Worker) flush(ctx context.Context, id string) (int, error) {
	args := &redis.XReadGroupArgs{
		Group:    w.cfg.Group,
		Consumer: w.cfg.Consumer,
		Streams:  []string{w.cfg.Stream, id},
		Count:    w.cfg.BatchSize,
	}
	streams, err := w.rdb.XReadGroup(ctx, args).Result()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	processed := 0
	for _, stream := range streams {
		for _, message := range stream.Messages {
			if err = w.publish(ctx, message); err != nil {
				return processed, err
			}
			pipe := w.rdb.TxPipeline()
			pipe.XAck(ctx, w.cfg.Stream, w.cfg.Group, message.ID)
			pipe.XDel(ctx, w.cfg.Stream, message.ID)
			if _, err = pipe.Exec(ctx); err != nil {
				return processed, fmt.Errorf("ack stream event %s: %w", message.ID, err)
			}
			processed++
		}
	}
	return processed, nil
}

func (w *Worker) publish(ctx context.Context, message redis.XMessage) error {
	eventType := field(message, "event_type")
	brigadeID := field(message, "brigade_id")
	occurredAt := field(message, "occurred_at")
	if brigadeID == "" || occurredAt == "" {
		return fmt.Errorf("invalid stream event %s", message.ID)
	}
	payloadFields := map[string]any{"brigade_id": brigadeID}
	switch eventType {
	case "BrigadeSignalLost":
		payloadFields["from"] = field(message, "from_status")
		payloadFields["to"] = field(message, "to_status")
		payloadFields["changed_at"] = occurredAt
	case "VehiclePositionUpdated":
		for _, name := range []string{"vehicle_id", "sequence", "latitude", "longitude", "speed_kmh", "accuracy_meters"} {
			payloadFields[name] = field(message, name)
		}
	default:
		return fmt.Errorf("unsupported stream event %s type %q", message.ID, eventType)
	}
	version := 1
	if parsed, parseErr := strconv.Atoi(field(message, "event_version")); parseErr == nil && parsed > 0 {
		version = parsed
	}
	payload, err := json.Marshal(
		eventPayload{
			EventID:      firstNonEmpty(field(message, "event_id"), message.ID),
			EventVersion: version,
			EventType:    eventType,
			OccurredAt:   occurredAt,
			Payload:      payloadFields,
		},
	)
	if err != nil {
		return fmt.Errorf("marshal stream event %s: %w", message.ID, err)
	}
	err = telemetry.WriteKafka(
		ctx,
		w.writer,
		kafka.Message{
			Key:   []byte(brigadeID),
			Value: payload,
			Headers: []kafka.Header{
				{Key: "event_id", Value: []byte(message.ID)},
				{Key: "event_type", Value: []byte(eventType)},
				{Key: "event_version", Value: []byte("1")},
			},
			Time: time.Now().UTC(),
		},
	)
	if err != nil {
		return fmt.Errorf("publish stream event %s: %w", message.ID, err)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func field(message redis.XMessage, name string) string {
	value, ok := message.Values[name]
	if !ok {
		return ""
	}
	return fmt.Sprint(value)
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
