package telemetry

import (
	"context"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	httpMeter = otel.Meter("gateway/http")

	httpRequestCount, _ = httpMeter.Int64Counter(
		"http.server.request.count",
		metric.WithDescription("Number of HTTP requests handled by the gateway."),
	)
	httpRequestDuration, _ = httpMeter.Float64Histogram(
		"http.server.request.duration",
		metric.WithDescription("Gateway HTTP request duration."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
	)
)

// ObserveHTTPRequest записывает RED-метрики с ограниченной cardinality.
// Контекст запроса позволяет OTLP-конвейеру прикрепить активную трассировку
// как exemplar.
func ObserveHTTPRequest(
	ctx context.Context,
	method string,
	route string,
	status int,
	duration time.Duration,
) {
	statusClass := strconv.Itoa(status/100) + "xx"
	attributes := metric.WithAttributes(
		attribute.String("http.request.method", method),
		attribute.String("http.route", route),
		attribute.String("http.response.status_class", statusClass),
	)
	httpRequestCount.Add(ctx, 1, attributes)
	httpRequestDuration.Record(ctx, duration.Seconds(), attributes)
}
