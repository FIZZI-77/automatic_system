package pkg

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const RequestIDHeader = "X-Request-ID"
const requestIDMetadataKey = "x-request-id"

type requestIDContextKey struct{}

func WithRequestID(ctx context.Context, id string) context.Context {
	if id = strings.TrimSpace(id); id != "" {
		return context.WithValue(ctx, requestIDContextKey{}, id)
	}
	return ctx
}
func RequestIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDContextKey{}).(string)
	return id, ok && id != ""
}
func RequestIDField(ctx context.Context) zap.Field {
	id, ok := RequestIDFromContext(ctx)
	if !ok {
		return zap.Skip()
	}
	return zap.String("request_id", id)
}

func RequestIDUnaryServerInterceptor(
	ctx context.Context,
	req any,
	_ *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	id := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get(requestIDMetadataKey); len(values) > 0 {
			id = values[0]
		}
	}
	if strings.TrimSpace(id) == "" {
		id = uuid.NewString()
	}
	return handler(WithRequestID(ctx, id), req)
}
