package completionconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"report/pkg/telemetry"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
	"report/models"
)

const (
	requestedEvent  = "ticket.completion_report.requested.v1"
	compensateEvent = "ticket.completion_report.compensation_requested.v1"
)

type Processor interface {
	Process(context.Context, models.CompletionReport) (models.CompletionReportResult, error)
	Compensate(context.Context, models.CompletionCompensation) error
}

type Worker struct {
	reader        *kafka.Reader
	writer        *kafka.Writer
	processor     Processor
	requestTopic  string
	resultTopic   string
	consumerGroup string
	logger        *zap.Logger
}

func New(
	brokers []string,
	requestTopic string,
	resultTopic string,
	groupID string,
	processor Processor,
	logger *zap.Logger,
) (*Worker, error) {
	if len(brokers) == 0 || strings.TrimSpace(requestTopic) == "" || strings.TrimSpace(resultTopic) == "" || strings.TrimSpace(groupID) == "" || processor == nil {
		return nil, errors.New("completion consumer: brokers, topics, group id and processor are required")
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Topic:          requestTopic,
		GroupID:        groupID,
		CommitInterval: 0,
		MinBytes:       1,
		MaxBytes:       10e6,
	})
	writer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		RequiredAcks: kafka.RequireAll,
	}

	return &Worker{
		reader:        reader,
		writer:        writer,
		processor:     processor,
		requestTopic:  requestTopic,
		resultTopic:   resultTopic,
		consumerGroup: groupID,
		logger:        logger,
	}, nil
}

func (w *Worker) Close() error {
	return errors.Join(w.reader.Close(), w.writer.Close())
}

func (w *Worker) Run(ctx context.Context) error {
	for {
		message, err := w.reader.FetchMessage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("fetch completion request: %w", err)
		}
		if err = telemetry.TraceKafkaConsumer(
			ctx,
			message,
			w.consumerGroup,
			w.handle,
		); err != nil {
			return err
		}
		if err = w.reader.CommitMessages(ctx, message); err != nil {
			return fmt.Errorf("commit completion request: %w", err)
		}
	}
}

func (w *Worker) handle(ctx context.Context, message kafka.Message) (err error) {
	eventType := header(message.Headers, "event_type")
	ctx, span := telemetry.Tracer("report/completion-saga").Start(ctx, "CompletionSaga.ProcessRequest")
	defer func() { telemetry.End(span, err) }()
	span.SetAttributes(
		attribute.String("saga.name", "completion_report"),
		attribute.String("messaging.event.type", eventType),
	)
	if eventType == compensateEvent {
		return w.handleCompensation(ctx, message)
	}
	if eventType != requestedEvent {
		return nil
	}
	var input models.CompletionReport
	if err := json.Unmarshal(message.Value, &input); err != nil {
		return w.publishDLQ(ctx, message, fmt.Errorf("decode completion request: %w", err))
	}
	result, processErr := w.processor.Process(ctx, input)
	eventType = "ticket.completion_report.generated.v1"
	payload := map[string]any{
		"work_report_id": input.WorkReportID,
		"file_id":        result.FileID,
		"name":           result.Name,
		"requested_by":   input.RequestedBy,
		"actor_roles":    input.ActorRoles,
	}
	if processErr != nil {
		eventType = "ticket.completion_report.failed.v1"
		payload = map[string]any{
			"work_report_id": input.WorkReportID,
			"error":          truncate(processErr.Error(), 2000),
		}
		w.logger.Error(
			"completion report generation failed",
			zap.String("work_report_id", input.WorkReportID),
			zap.Error(processErr),
		)
	}
	if err := w.publish(ctx, w.resultTopic, eventType, input.WorkReportID, payload, nil); err != nil {
		if processErr == nil {
			compensation := models.CompletionCompensation{
				WorkReportID: input.WorkReportID,
				FileID:       result.FileID,
				RequestedBy:  input.RequestedBy,
				ActorRoles:   input.ActorRoles,
			}
			if compensateErr := w.processor.Compensate(ctx, compensation); compensateErr != nil {
				return errors.Join(err, fmt.Errorf("compensate unpublished completion: %w", compensateErr))
			}
		}
		return err
	}
	return nil
}

func (w *Worker) handleCompensation(ctx context.Context, message kafka.Message) (err error) {
	ctx, span := telemetry.Tracer("report/completion-saga").Start(ctx, "CompletionSaga.Compensate")
	defer func() { telemetry.End(span, err) }()
	span.SetAttributes(attribute.String("saga.name", "completion_report"))

	var input models.CompletionCompensation
	if err := json.Unmarshal(message.Value, &input); err != nil {
		return w.publishDLQ(ctx, message, fmt.Errorf("decode completion compensation: %w", err))
	}

	eventType := "ticket.completion_report.compensated.v1"
	payload := map[string]any{
		"work_report_id": input.WorkReportID,
		"file_id":        input.FileID,
		"requested_by":   input.RequestedBy,
		"actor_roles":    input.ActorRoles,
	}
	if err := w.processor.Compensate(ctx, input); err != nil {
		eventType = "ticket.completion_report.compensation_failed.v1"
		payload["error"] = truncate(err.Error(), 2000)
		w.logger.Error(
			"completion report compensation failed",
			zap.String("work_report_id", input.WorkReportID),
			zap.String("file_id", input.FileID),
			zap.Error(err),
		)
	}

	return w.publish(ctx, w.resultTopic, eventType, input.WorkReportID, payload, nil)
}

func (w *Worker) publishDLQ(ctx context.Context, message kafka.Message, processErr error) (err error) {
	ctx, span := telemetry.Tracer("report/dlq").Start(ctx, "DLQ.Publish")
	defer func() { telemetry.End(span, err) }()
	span.SetAttributes(attribute.String("messaging.destination.name", w.requestTopic+".dlq"))

	headers := append([]kafka.Header(nil), message.Headers...)
	headers = append(headers, kafka.Header{
		Key:   "x-error",
		Value: []byte(truncate(processErr.Error(), 1000)),
	})

	return telemetry.WriteKafka(ctx, w.writer, kafka.Message{
		Topic:   w.requestTopic + ".dlq",
		Key:     message.Key,
		Value:   message.Value,
		Headers: headers,
		Time:    time.Now().UTC(),
	})
}

func (w *Worker) publish(ctx context.Context, topic, eventType, key string, payload any, headers []kafka.Header) error {
	value, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	headers = append(headers,
		kafka.Header{Key: "event_id", Value: []byte(uuid.NewString())},
		kafka.Header{Key: "event_type", Value: []byte(eventType)},
	)
	return telemetry.WriteKafka(ctx, w.writer, kafka.Message{
		Topic:   topic,
		Key:     []byte(key),
		Value:   value,
		Headers: headers,
		Time:    time.Now().UTC(),
	})
}

func header(headers []kafka.Header, key string) string {
	for _, value := range headers {
		if strings.EqualFold(value.Key, key) {
			return string(value.Value)
		}
	}
	return ""
}

func truncate(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}
	return value[:maxLen]
}
