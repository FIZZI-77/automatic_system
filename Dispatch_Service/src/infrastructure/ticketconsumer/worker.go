package ticketconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"dispatch/models"
	"dispatch/pkg/telemetry"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

const retryHeader = "x-retry-count"

type AutoDispatcher interface {
	AutoDispatch(context.Context, *models.AutoInput) (*models.Operation, error)
}

type Config struct {
	Brokers        []string
	Topic          string
	GroupID        string
	ActorID        uuid.UUID
	CandidateLimit int32
	MaxAttempts    int
}

type Worker struct {
	reader    *kafka.Reader
	retry     *kafka.Reader
	writer    *kafka.Writer
	dispatch  AutoDispatcher
	config    Config
	logger    *zap.Logger
	closeOnce sync.Once
}

type ticketCreated struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	TicketID  string `json:"ticket_id"`
	Priority  string `json:"priority"`
}

func New(dispatch AutoDispatcher, config Config, logger *zap.Logger) (*Worker, error) {
	config.Brokers = clean(config.Brokers)
	if dispatch == nil || len(config.Brokers) == 0 || strings.TrimSpace(config.Topic) == "" || strings.TrimSpace(config.GroupID) == "" || config.ActorID == uuid.Nil {
		return nil, errors.New("ticket consumer: dispatcher, brokers, topic, group and actor id are required")
	}
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = 5
	}
	if config.CandidateLimit <= 0 {
		config.CandidateLimit = 10
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	newReader := func(topic, group string) *kafka.Reader {
		return kafka.NewReader(kafka.ReaderConfig{Brokers: config.Brokers, Topic: topic, GroupID: group, MinBytes: 1, MaxBytes: 10e6, CommitInterval: 0})
	}
	return &Worker{
		reader: newReader(config.Topic, config.GroupID), retry: newReader(config.Topic+".retry", config.GroupID+".retry"),
		writer:   &kafka.Writer{Addr: kafka.TCP(config.Brokers...), RequiredAcks: kafka.RequireAll},
		dispatch: dispatch, config: config, logger: logger,
	}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsChannel := make(chan error, 2)
	var workers sync.WaitGroup
	for _, reader := range []*kafka.Reader{w.reader, w.retry} {
		workers.Add(1)
		go func(reader *kafka.Reader) {
			defer workers.Done()
			errorsChannel <- w.consume(ctx, reader)
		}(reader)
	}
	select {
	case <-ctx.Done():
		cancel()
		workers.Wait()
		return nil
	case err := <-errorsChannel:
		cancel()
		workers.Wait()
		return err
	}
}

func (w *Worker) Close() error {
	var result error
	w.closeOnce.Do(func() {
		result = errors.Join(w.reader.Close(), w.retry.Close(), w.writer.Close())
	})
	return result
}

func (w *Worker) consume(ctx context.Context, reader *kafka.Reader) error {
	for {
		message, err := reader.FetchMessage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			w.logger.Warn("fetch ticket event failed", zap.Error(err))
			if !wait(ctx, time.Second) {
				return nil
			}
			continue
		}
		if strings.HasSuffix(message.Topic, ".retry") && !wait(ctx, time.Duration(1<<min(max(retries(message.Headers), 1), 5))*time.Second) {
			return nil
		}
		err = telemetry.TraceKafkaConsumer(ctx, message, w.config.GroupID, w.apply)
		if err != nil {
			w.logger.Warn("ticket event processing failed", zap.Error(err), zap.Int64("offset", message.Offset))
			if publishErr := w.retryOrDLQ(ctx, message, err); publishErr != nil {
				return errors.Join(err, publishErr)
			}
		}
		if err = reader.CommitMessages(ctx, message); err != nil {
			return fmt.Errorf("commit ticket event: %w", err)
		}
	}
}

func (w *Worker) apply(ctx context.Context, message kafka.Message) error {
	var event ticketCreated
	if err := json.Unmarshal(message.Value, &event); err != nil {
		return fmt.Errorf("decode ticket event: %w", err)
	}
	eventType := first(event.EventType, header(message.Headers, "event_type"))
	if !strings.EqualFold(eventType, "ticket.created") || !strings.EqualFold(event.Priority, "EMERGENCY") {
		return nil
	}
	eventID, err := uuid.Parse(first(event.EventID, header(message.Headers, "event_id")))
	if err != nil {
		return fmt.Errorf("invalid event_id: %w", err)
	}
	ticketID, err := uuid.Parse(event.TicketID)
	if err != nil {
		return fmt.Errorf("invalid ticket_id: %w", err)
	}
	_, err = w.dispatch.AutoDispatch(ctx, &models.AutoInput{
		TicketID: ticketID, RequestedBy: w.config.ActorID, CandidateLimit: w.config.CandidateLimit, TriggerEventID: &eventID,
	})
	return err
}

func (w *Worker) retryOrDLQ(ctx context.Context, message kafka.Message, processErr error) error {
	attempt := retries(message.Headers) + 1
	topic := w.config.Topic + ".retry"
	if attempt >= w.config.MaxAttempts {
		topic = w.config.Topic + ".dlq"
	}
	return telemetry.WriteKafka(ctx, w.writer, kafka.Message{
		Topic: topic, Key: message.Key, Value: message.Value,
		Headers: retryHeaders(message.Headers, attempt, processErr), Time: time.Now().UTC(),
	})
}

func wait(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func retries(headers []kafka.Header) int {
	value, _ := strconv.Atoi(header(headers, retryHeader))
	return max(value, 0)
}

func retryHeaders(headers []kafka.Header, attempt int, processErr error) []kafka.Header {
	result := make([]kafka.Header, 0, len(headers)+2)
	for _, value := range headers {
		if !strings.EqualFold(value.Key, retryHeader) && !strings.EqualFold(value.Key, "x-error") {
			result = append(result, value)
		}
	}
	errorMessage := processErr.Error()
	if len(errorMessage) > 1000 {
		errorMessage = errorMessage[:1000]
	}
	return append(result,
		kafka.Header{Key: retryHeader, Value: []byte(strconv.Itoa(attempt))},
		kafka.Header{Key: "x-error", Value: []byte(errorMessage)},
	)
}

func header(headers []kafka.Header, key string) string {
	for _, value := range headers {
		if strings.EqualFold(value.Key, key) {
			return string(value.Value)
		}
	}
	return ""
}

func first(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func clean(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}
