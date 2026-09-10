package main

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func TestDefaultTimeoutInterceptorAddsDeadline(t *testing.T) {
	t.Parallel()
	interceptor := defaultTimeoutInterceptor(time.Second)
	invoked := false
	err := interceptor(t.Context(), "/dispatch.Test/Call", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		invoked = true
		if _, ok := ctx.Deadline(); !ok {
			t.Error("defaultTimeoutInterceptor() context has no deadline")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("defaultTimeoutInterceptor() error = %v", err)
	}
	if !invoked {
		t.Fatal("defaultTimeoutInterceptor() invoked = false, want true")
	}
}

func TestStopGRPCServerReturnsForIdleServer(t *testing.T) {
	t.Parallel()
	server := grpc.NewServer()
	done := make(chan struct{})
	go func() {
		stopGRPCServer(server, time.Second, zap.NewNop())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stopGRPCServer(idle) did not return")
	}
}
