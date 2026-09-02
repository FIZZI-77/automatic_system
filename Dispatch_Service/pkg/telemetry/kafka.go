package telemetry

import (
	"context"

	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

func WriteKafka(ctx context.Context, writer *kafka.Writer, message kafka.Message) error {
	ctx, span := Tracer("kafka").Start(
		ctx,
		"publish "+message.Topic,
		trace.WithSpanKind(trace.SpanKindProducer),
		trace.WithAttributes(
			attribute.String("messaging.system", "kafka"),
			attribute.String("messaging.destination.name", message.Topic),
		),
	)
	carrier := newKafkaHeaderCarrier(message.Headers)
	Inject(ctx, carrier)
	message.Headers = carrier.headers()
	err := writer.WriteMessages(ctx, message)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
	return err
}

func TraceKafkaConsumer(ctx context.Context, message kafka.Message, group string, process func(context.Context, kafka.Message) error) error {
	carrier := newKafkaHeaderCarrier(message.Headers)
	ctx = Extract(ctx, carrier)
	ctx, span := Tracer("kafka").Start(ctx, "process "+message.Topic,
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.String("messaging.system", "kafka"),
			attribute.String("messaging.destination.name", message.Topic),
			attribute.String("messaging.consumer.group.name", group),
			attribute.Int("messaging.kafka.partition", message.Partition),
		),
	)
	err := process(ctx, message)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
	return err
}

type kafkaHeaderCarrier map[string]string

func (carrier kafkaHeaderCarrier) Get(key string) string { return carrier[key] }
func (carrier kafkaHeaderCarrier) Set(key, value string) { carrier[key] = value }
func (carrier kafkaHeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(carrier))
	for key := range carrier {
		keys = append(keys, key)
	}
	return keys
}
func (carrier kafkaHeaderCarrier) headers() []kafka.Header {
	headers := make([]kafka.Header, 0, len(carrier))
	for key, value := range carrier {
		headers = append(headers, kafka.Header{Key: key, Value: []byte(value)})
	}
	return headers
}
func newKafkaHeaderCarrier(headers []kafka.Header) kafkaHeaderCarrier {
	carrier := make(kafkaHeaderCarrier, len(headers))
	for _, header := range headers {
		carrier[header.Key] = string(header.Value)
	}
	return carrier
}

var _ propagation.TextMapCarrier = kafkaHeaderCarrier{}
