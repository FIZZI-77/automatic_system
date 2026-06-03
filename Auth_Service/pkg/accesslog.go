package pkg

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

func AccessLogUnaryServerInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		resp, err := handler(ctx, req)
		code := status.Code(err)

		fields := []zap.Field{
			RequestIDField(ctx),
			zap.String("grpc_method", info.FullMethod),
			zap.String("code", code.String()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
		}

		if err != nil {
			logger.Warn("gRPC request completed", append(fields, zap.Error(err))...)
			return resp, err
		}

		logger.Info("gRPC request completed", fields...)
		return resp, nil
	}
}
