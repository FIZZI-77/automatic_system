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
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return ctx
	}

	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

func RequestIDFromContext(ctx context.Context) (string, bool) {
	requestID, ok := ctx.Value(requestIDContextKey{}).(string)
	if !ok || requestID == "" {
		return "", false
	}

	return requestID, true
}

func RequestIDField(ctx context.Context) zap.Field {
	requestID, ok := RequestIDFromContext(ctx)
	if !ok {
		return zap.Skip()
	}

	return zap.String("request_id", requestID)
}

func RequestIDUnaryServerInterceptor(
	ctx context.Context,
	req interface{},
	_ *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		values := md.Get(requestIDMetadataKey)
		if len(values) > 0 {
			ctx = WithRequestID(ctx, values[0])
		}
	}

	return handler(ctx, req)
}

func RequestIDUnaryClientInterceptor(
	ctx context.Context,
	method string,
	req interface{},
	reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	if requestID, ok := RequestIDFromContext(ctx); ok {
		ctx = metadata.AppendToOutgoingContext(ctx, requestIDMetadataKey, requestID)
	}
	return invoker(ctx, method, req, reply, cc, opts...)
}
