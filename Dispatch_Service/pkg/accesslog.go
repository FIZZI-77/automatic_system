package pkg

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func AccessLogUnaryServerInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		startedAt := time.Now()
		response, err := handler(ctx, req)
		code := status.Code(err)
		spanContext := trace.SpanContextFromContext(ctx)
		fields := []zap.Field{
			zap.String("trace_id", spanContext.TraceID().String()),
			zap.String("span_id", spanContext.SpanID().String()),
			zap.String("grpc_method", info.FullMethod),
			zap.String("code", code.String()),
			zap.String("layer", "transport.grpc"),
			zap.Duration("duration", time.Since(startedAt)),
		}
		if err == nil {
			logger.Info("gRPC request completed", fields...)
			return response, nil
		}

		fields = append(fields, zap.Error(err))
		if isServerError(code) {
			logger.Error("gRPC request failed", fields...)
		} else {
			logger.Warn("gRPC request rejected", fields...)
		}
		return response, err
	}
}

func isServerError(code codes.Code) bool {
	switch code {
	case codes.Unknown, codes.Internal, codes.DataLoss, codes.Unavailable:
		return true
	default:
		return false
	}
}
