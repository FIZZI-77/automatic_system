package idempotency

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	Header      = "X-Idempotency-Key"
	MetadataKey = "x-idempotency-key"
)

type contextKey struct{}

func WithContext(ctx context.Context, key string) context.Context {
	key = strings.TrimSpace(key)
	if key == "" {
		return ctx
	}

	return context.WithValue(ctx, contextKey{}, key)
}

func FromContext(ctx context.Context) (string, bool) {
	key, ok := ctx.Value(contextKey{}).(string)
	if !ok || key == "" {
		return "", false
	}

	return key, true
}

func UnaryClientInterceptor(
	ctx context.Context,
	method string,
	req interface{},
	reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	if key, ok := FromContext(ctx); ok {
		ctx = metadata.AppendToOutgoingContext(ctx, MetadataKey, key)
	}

	return invoker(ctx, method, req, reply, cc, opts...)
}
