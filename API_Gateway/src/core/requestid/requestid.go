package requestid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	Header      = "X-Request-ID"
	MetadataKey = "x-request-id"
)

type contextKey struct{}

func New() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}

	return hex.EncodeToString(bytes[:])
}

func WithContext(ctx context.Context, requestID string) context.Context {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return ctx
	}

	return context.WithValue(ctx, contextKey{}, requestID)
}

func FromContext(ctx context.Context) (string, bool) {
	requestID, ok := ctx.Value(contextKey{}).(string)
	if !ok || requestID == "" {
		return "", false
	}

	return requestID, true
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
	if requestID, ok := FromContext(ctx); ok {
		ctx = metadata.AppendToOutgoingContext(ctx, MetadataKey, requestID)
	}

	return invoker(ctx, method, req, reply, cc, opts...)
}
