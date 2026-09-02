package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	prometheusexporter "go.opentelemetry.io/otel/exporters/prometheus"
	metricapi "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/stats"
)

const defaultSampleRatio = 1.0

var (
	unknownVersionOnce    sync.Once
	unknownVersionCounter metricapi.Int64Counter
	consumerMetricsOnce   sync.Once
	consumerOperations    metricapi.Int64Counter
	consumerErrors        metricapi.Int64Counter
	consumerDuration      metricapi.Float64Histogram
	consumerLag           metricapi.Int64Gauge
)

func RecordUnknownEventVersion(ctx context.Context, topic string, version uint32) {
	unknownVersionOnce.Do(func() {
		unknownVersionCounter, _ = otel.Meter("analytics/events").Int64Counter(
			"analytics_unknown_event_versions_total",
			metricapi.WithDescription("Events excluded from projections because their version is unsupported"),
		)
	})
	if unknownVersionCounter == nil {
		return
	}
	unknownVersionCounter.Add(ctx, 1, metricapi.WithAttributes(
		attribute.String("topic", topic),
		attribute.Int64("event_version", int64(version)),
	))
}

// RecordConsumerResult records bounded per-topic throughput, errors, latency,
// and the latest kafka-go consumer-group lag observation.
func RecordConsumerResult(ctx context.Context, topic string, duration time.Duration, lag int64, err error) {
	consumerMetricsOnce.Do(func() {
		meter := otel.Meter("analytics/consumer")
		consumerOperations, _ = meter.Int64Counter("analytics_consumer_operations_total")
		consumerErrors, _ = meter.Int64Counter("analytics_consumer_errors_total")
		consumerDuration, _ = meter.Float64Histogram(
			"analytics_consumer_processing_duration_seconds",
			metricapi.WithDescription("Domain event decode, projection and commit duration"),
		)
		consumerLag, _ = meter.Int64Gauge(
			"analytics_consumer_lag_messages",
			metricapi.WithDescription("kafka-go consumer group lag sampled after message processing"),
		)
	})
	attributes := metricapi.WithAttributes(attribute.String("topic", topic))
	if consumerOperations != nil {
		consumerOperations.Add(ctx, 1, attributes)
	}
	if err != nil && consumerErrors != nil {
		consumerErrors.Add(ctx, 1, attributes)
	}
	if consumerDuration != nil {
		consumerDuration.Record(ctx, duration.Seconds(), attributes)
	}
	if lag >= 0 && consumerLag != nil {
		consumerLag.Record(ctx, lag, attributes)
	}
}

// Providers owns the process-wide OpenTelemetry providers.
type Providers struct {
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	metricsServer  *http.Server
}

// Init configures OTLP traces and a Prometheus metrics endpoint. The trace
// exporter connects asynchronously, so a temporarily unavailable collector
// does not prevent the service from starting.
func Init(ctx context.Context, serviceName string) (*Providers, error) {
	res, err := newResource(ctx, serviceName)
	if err != nil {
		return nil, err
	}

	traceExporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	metricExporter, err := prometheusexporter.New(
		prometheusexporter.WithRegisterer(registry),
	)
	if err != nil {
		_ = traceExporter.Shutdown(ctx)
		return nil, fmt.Errorf("create Prometheus metric exporter: %w", err)
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRatio()))),
	)
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(metricExporter),
	)
	metricsListener, err := net.Listen("tcp", env("METRICS_ADDR", ":9464"))
	if err != nil {
		_ = tracerProvider.Shutdown(ctx)
		_ = meterProvider.Shutdown(ctx)
		return nil, fmt.Errorf("listen for Prometheus metrics: %w", err)
	}
	metricsServer := &http.Server{
		Handler: promhttp.HandlerFor(registry, promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if serveErr := metricsServer.Serve(metricsListener); serveErr != nil &&
			!errors.Is(serveErr, http.ErrServerClosed) {
			log.Printf("Prometheus metrics server failed: %v", serveErr)
		}
	}()

	otel.SetTracerProvider(tracerProvider)
	otel.SetMeterProvider(meterProvider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if err := runtime.Start(runtime.WithMinimumReadMemStatsInterval(15 * time.Second)); err != nil {
		_ = tracerProvider.Shutdown(ctx)
		_ = meterProvider.Shutdown(ctx)
		return nil, fmt.Errorf("start runtime instrumentation: %w", err)
	}

	return &Providers{
		tracerProvider: tracerProvider,
		meterProvider:  meterProvider,
		metricsServer:  metricsServer,
	}, nil
}

// Close flushes pending telemetry with a bounded process-shutdown deadline.
func (p *Providers) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return p.Shutdown(ctx)
}

// Shutdown flushes pending telemetry and stops both providers.
func (p *Providers) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}

	return errors.Join(
		p.metricsServer.Shutdown(ctx),
		p.meterProvider.Shutdown(ctx),
		p.tracerProvider.Shutdown(ctx),
	)
}

// GRPCServerOption instruments unary and streaming server calls.
func GRPCServerOption() grpc.ServerOption {
	return grpc.StatsHandler(otelgrpc.NewServerHandler())
}

// GRPCClientOption instruments unary and streaming client calls.
func GRPCClientOption() grpc.DialOption {
	return grpc.WithStatsHandler(otelgrpc.NewClientHandler())
}

// HTTPHandler instruments inbound HTTP traffic and excludes operational probes.
func HTTPHandler(handler http.Handler, operation string) http.Handler {
	return otelhttp.NewHandler(
		handler,
		operation,
		otelhttp.WithFilter(func(request *http.Request) bool {
			switch request.URL.Path {
			case "/livez", "/readyz", "/metrics":
				return false
			default:
				return true
			}
		}),
	)
}

// HTTPTransport instruments outbound HTTP traffic.
func HTTPTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(base)
}

// Inject writes the current trace and baggage into a message carrier.
func Inject(ctx context.Context, carrier propagation.TextMapCarrier) {
	otel.GetTextMapPropagator().Inject(ctx, carrier)
}

// Extract restores trace and baggage from a message carrier.
func Extract(ctx context.Context, carrier propagation.TextMapCarrier) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, carrier)
}

// Tracer returns a tracer scoped to a service package.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

func newResource(ctx context.Context, serviceName string) (*resource.Resource, error) {
	return resource.New(
		ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithOS(),
		resource.WithProcess(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(env("OTEL_SERVICE_VERSION", "dev")),
			semconv.DeploymentEnvironmentName(env("OTEL_DEPLOYMENT_ENVIRONMENT", "local")),
		),
	)
}

func sampleRatio() float64 {
	value := env("OTEL_TRACES_SAMPLER_ARG", strconv.FormatFloat(defaultSampleRatio, 'f', 2, 64))
	ratio, err := strconv.ParseFloat(value, 64)
	if err != nil || ratio < 0 || ratio > 1 {
		return defaultSampleRatio
	}
	return ratio
}

func env(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

// Compile-time checks keep option return types explicit when gRPC APIs evolve.
var (
	_ grpc.ServerOption = GRPCServerOption()
	_ grpc.DialOption   = GRPCClientOption()
	_ stats.Handler     = otelgrpc.NewServerHandler()
)
