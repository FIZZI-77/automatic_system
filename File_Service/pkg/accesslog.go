package pkg

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

func AccessLogUnaryServerInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		startedAt := time.Now()
		response, err := handler(ctx, req)
		fields := []zap.Field{
			RequestIDField(ctx),
			zap.String("trace_id", trace.SpanContextFromContext(ctx).TraceID().String()),
			zap.String("span_id", trace.SpanContextFromContext(ctx).SpanID().String()),
			zap.String("grpc_method", info.FullMethod),
			zap.String("code", status.Code(err).String()),
			zap.Duration("duration", time.Since(startedAt)),
		}
		if err != nil {
			logger.Warn("gRPC request completed", append(fields, zap.Error(err))...)
		} else {
			logger.Info("gRPC request completed", fields...)
		}
		return response, err
	}
}
