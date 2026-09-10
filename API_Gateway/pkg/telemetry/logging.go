package telemetry

import (
	"context"
	"log/slog"
	"os"

	"go.opentelemetry.io/otel/trace"
)

// TraceHandler enriches every context-aware slog record with the active span.
type TraceHandler struct {
	slog.Handler
}

func (h TraceHandler) Handle(ctx context.Context, record slog.Record) error {
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.IsValid() {
		record.AddAttrs(
			slog.String("trace_id", spanContext.TraceID().String()),
			slog.String("span_id", spanContext.SpanID().String()),
		)
	}

	return h.Handler.Handle(ctx, record)
}

func (h TraceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return TraceHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h TraceHandler) WithGroup(name string) slog.Handler {
	return TraceHandler{Handler: h.Handler.WithGroup(name)}
}

// NewJSONLogger creates a JSON logger with trace correlation.
func NewJSONLogger(serviceName string, level slog.Leveler) *slog.Logger {
	handler := slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{Level: level},
	)

	return slog.New(TraceHandler{Handler: handler}).With(
		slog.String("service.name", serviceName),
	)
}
