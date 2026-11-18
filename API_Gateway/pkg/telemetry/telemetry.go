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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	prometheusexporter "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/stats"
)

const defaultSampleRatio = 1.0

// Providers хранит общие для процесса провайдеры OpenTelemetry.
type Providers struct {
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *metric.MeterProvider
	metricsServer  *http.Server
}

// Init настраивает экспорт трассировок через OTLP и endpoint метрик Prometheus.
// Экспортёр подключается асинхронно, поэтому временная недоступность коллектора
// не мешает запуску сервиса.
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
	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metricExporter),
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

// Close сбрасывает накопленную телеметрию в пределах срока завершения процесса.
func (p *Providers) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return p.Shutdown(ctx)
}

// Shutdown сбрасывает накопленную телеметрию и останавливает оба провайдера.
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

// GRPCServerOption добавляет телеметрию к унарным и потоковым серверным вызовам.
func GRPCServerOption() grpc.ServerOption {
	return grpc.StatsHandler(otelgrpc.NewServerHandler())
}

// GRPCClientOption добавляет телеметрию к унарным и потоковым клиентским вызовам.
func GRPCClientOption() grpc.DialOption {
	return grpc.WithStatsHandler(otelgrpc.NewClientHandler())
}

// HTTPHandler добавляет телеметрию к входящему HTTP-трафику и исключает служебные проверки.
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

// HTTPTransport добавляет телеметрию к исходящему HTTP-трафику.
func HTTPTransport(base http.RoundTripper) http.RoundTripper {

	if base == nil {
		base = http.DefaultTransport
	}

	return otelhttp.NewTransport(base)
}

// Inject записывает текущий контекст трассировки и baggage в носитель сообщения.
func Inject(ctx context.Context, carrier propagation.TextMapCarrier) {
	otel.GetTextMapPropagator().Inject(ctx, carrier)
}

// Extract восстанавливает контекст трассировки и baggage из носителя сообщения.
func Extract(ctx context.Context, carrier propagation.TextMapCarrier) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, carrier)
}

// Tracer возвращает трассировщик, привязанный к пакету сервиса.
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

// Проверки времени компиляции фиксируют типы возвращаемых gRPC-параметров при изменении API.
var (
	_ grpc.ServerOption = GRPCServerOption()
	_ grpc.DialOption   = GRPCClientOption()
	_ stats.Handler     = otelgrpc.NewServerHandler()
)
