package telemetry

import (
	"context"
	"strconv"

	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// KafkaHeaderCarrier adapts kafka-go headers to the OpenTelemetry propagator.
type KafkaHeaderCarrier []kafka.Header

func (carrier KafkaHeaderCarrier) Get(key string) string {
	for i := len(carrier) - 1; i >= 0; i-- {
		if carrier[i].Key == key {
			return string(carrier[i].Value)
		}
	}
	return ""
}

func (carrier KafkaHeaderCarrier) Set(key string, value string) {
	for i := range carrier {
		if carrier[i].Key == key {
			carrier[i].Value = []byte(value)
			return
		}
	}
}

func (carrier KafkaHeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(carrier))
	for _, header := range carrier {
		keys = append(keys, header.Key)
	}
	return keys
}

// InjectKafka propagates the active trace through Kafka message headers.
func InjectKafka(ctx context.Context, message *kafka.Message) {
	carrier := newKafkaHeaderMap(message.Headers)
	Inject(ctx, carrier)
	message.Headers = carrier.headers()
}

// StartKafkaConsumer extracts the producer context and starts a consumer span.
func StartKafkaConsumer(
	ctx context.Context,
	message kafka.Message,
	consumerGroup string,
) (context.Context, trace.Span) {
	ctx = Extract(ctx, newKafkaHeaderMap(message.Headers))

	return Tracer("kafka").Start(
		ctx,
		"consume "+message.Topic,
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.String("messaging.system", "kafka"),
			attribute.String("messaging.operation.name", "process"),
			attribute.String("messaging.destination.name", message.Topic),
			attribute.String("messaging.consumer.group.name", consumerGroup),
			attribute.Int("messaging.kafka.partition", message.Partition),
			attribute.String("messaging.kafka.offset", strconv.FormatInt(message.Offset, 10)),
		),
	)
}

// TraceKafkaConsumer runs message processing in a consumer span restored from
// the message headers. Offset commits intentionally remain outside process.
func TraceKafkaConsumer(
	ctx context.Context,
	message kafka.Message,
	consumerGroup string,
	process func(context.Context, kafka.Message) error,
) error {
	ctx, span := StartKafkaConsumer(ctx, message, consumerGroup)
	err := process(ctx, message)
	End(span, err)
	return err
}

// StartKafkaProducer starts a producer span and injects it into the message.
func StartKafkaProducer(ctx context.Context, message *kafka.Message) (context.Context, trace.Span) {
	ctx, span := Tracer("kafka").Start(
		ctx,
		"publish "+message.Topic,
		trace.WithSpanKind(trace.SpanKindProducer),
		trace.WithAttributes(
			attribute.String("messaging.system", "kafka"),
			attribute.String("messaging.operation.name", "publish"),
			attribute.String("messaging.destination.name", message.Topic),
		),
	)
	InjectKafka(ctx, message)
	return ctx, span
}

// WriteKafka creates a producer span, injects its context into every message,
// and records the broker write result.
func WriteKafka(ctx context.Context, writer *kafka.Writer, messages ...kafka.Message) error {
	if len(messages) == 0 {
		return nil
	}

	ctx, span := Tracer("kafka").Start(
		ctx,
		"publish "+messages[0].Topic,
		trace.WithSpanKind(trace.SpanKindProducer),
		trace.WithAttributes(
			attribute.String("messaging.system", "kafka"),
			attribute.String("messaging.operation.name", "publish"),
			attribute.String("messaging.destination.name", messages[0].Topic),
			attribute.Int("messaging.batch.message_count", len(messages)),
		),
	)
	for i := range messages {
		InjectKafka(ctx, &messages[i])
	}

	err := writer.WriteMessages(ctx, messages...)
	End(span, err)
	return err
}

// End records an operation error, sets the span status, and ends the span.
func End(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
}

type kafkaHeaderMap map[string]string

func (carrier kafkaHeaderMap) Get(key string) string {
	return carrier[key]
}

func (carrier kafkaHeaderMap) Set(key string, value string) {
	carrier[key] = value
}

func (carrier kafkaHeaderMap) Keys() []string {
	keys := make([]string, 0, len(carrier))
	for key := range carrier {
		keys = append(keys, key)
	}
	return keys
}

func (carrier kafkaHeaderMap) headers() []kafka.Header {
	headers := make([]kafka.Header, 0, len(carrier))
	for key, value := range carrier {
		headers = append(headers, kafka.Header{Key: key, Value: []byte(value)})
	}
	return headers
}

func kafkaHeaderMapFromCarrier(carrier propagation.TextMapCarrier) kafkaHeaderMap {
	headers := make(kafkaHeaderMap, len(carrier.Keys()))
	for _, key := range carrier.Keys() {
		headers[key] = carrier.Get(key)
	}
	return headers
}

func newKafkaHeaderMap(headers []kafka.Header) kafkaHeaderMap {
	carrier := make(kafkaHeaderMap, len(headers))
	for _, header := range headers {
		carrier[header.Key] = string(header.Value)
	}
	return carrier
}

// Keep the carrier contract explicit.
var _ propagation.TextMapCarrier = kafkaHeaderMap{}
