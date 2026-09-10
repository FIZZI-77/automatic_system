package pkg

import (
	"context"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const requestIDMetadataKey = "x-request-id"

type requestIDContextKey struct{}

func WithRequestID(ctx context.Context, requestID string) context.Context {
	if requestID = strings.TrimSpace(requestID); requestID == "" {
		return ctx
	}
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

func RequestIDField(ctx context.Context) zap.Field {
	requestID, _ := ctx.Value(requestIDContextKey{}).(string)
	if requestID == "" {
		return zap.Skip()
	}
	return zap.String("request_id", requestID)
}

func RequestIDUnaryServerInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get(requestIDMetadataKey); len(values) > 0 {
			ctx = WithRequestID(ctx, values[0])
		}
	}
	return handler(ctx, req)
}
