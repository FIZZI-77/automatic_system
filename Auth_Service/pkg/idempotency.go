package pkg

import (
	"context"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const idempotencyKeyMetadataKey = "x-idempotency-key"

type idempotencyKeyContextKey struct{}

func WithIdempotencyKey(ctx context.Context, key string) context.Context {
	key = strings.TrimSpace(key)
	if key == "" {
		return ctx
	}

	return context.WithValue(ctx, idempotencyKeyContextKey{}, key)
}

func IdempotencyKeyFromContext(ctx context.Context) (string, bool) {
	key, ok := ctx.Value(idempotencyKeyContextKey{}).(string)
	if !ok || key == "" {
		return "", false
	}

	return key, true
}

func IdempotencyKeyField(ctx context.Context) zap.Field {
	key, ok := IdempotencyKeyFromContext(ctx)
	if !ok {
		return zap.Skip()
	}

	return zap.String("idempotency_key", key)
}

func IdempotencyKeyUnaryServerInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		values := md.Get(idempotencyKeyMetadataKey)
		if len(values) > 0 {
			ctx = WithIdempotencyKey(ctx, values[0])
		}
	}

	return handler(ctx, req)
}
