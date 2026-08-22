package pkg

import (
	"context"
	"strings"

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

func IdempotencyKeyUnaryServerInterceptor(
	ctx context.Context,
	req interface{},
	_ *grpc.UnaryServerInfo,
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
