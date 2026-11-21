package grpcbreaker

import (
	"context"
	"errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestTripRecoveryAndSingleProbe(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		interceptor := UnaryClient("Department", DefaultConfig(), nil)
		var calls atomic.Int32
		invoke := func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
			calls.Add(1)
			return status.Error(codes.Unavailable, "offline")
		}
		call := func(f grpc.UnaryInvoker) error {
			return interceptor(context.Background(), "/service/Get", nil, nil, nil, f)
		}
		for range 5 {
			if err := call(invoke); status.Code(err) != codes.Unavailable {
				t.Fatalf("call(failing) = %v", err)
			}
		}
		if err := call(invoke); !errors.Is(err, ErrRejected) || status.Code(err) != codes.Unavailable || calls.Load() != 5 {
			t.Fatalf("call(open) = %v calls=%d; want local rejection and 5 calls", err, calls.Load())
		}
		time.Sleep(61 * time.Second)
		started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			done <- call(func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
				close(started)
				<-release
				return nil
			})
		}()
		<-started
		if err := call(invoke); !errors.Is(err, ErrRejected) {
			t.Errorf("call(second probe) = %v; want local rejection", err)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatalf("call(probe) = %v", err)
		}
		if err := call(func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error { return nil }); err != nil {
			t.Fatalf("call(recovered) = %v", err)
		}
	})
}
func TestFailedProbeReopens(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.FailureThreshold = 1
		interceptor := UnaryClient("Routing", cfg, nil)
		calls := 0
		invoke := func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
			calls++
			return status.Error(codes.Unavailable, "offline")
		}
		call := func() error { return interceptor(context.Background(), "/routing/Rank", nil, nil, nil, invoke) }
		_ = call()
		time.Sleep(61 * time.Second)
		_ = call()
		if err := call(); !errors.Is(err, ErrRejected) || calls != 2 {
			t.Fatalf("call(after failed probe) = %v calls=%d; want rejection and 2 calls", err, calls)
		}
	})
}
func TestBusinessErrorsAndParentCancellationDoNotTrip(t *testing.T) {
	t.Parallel()
	for _, code := range []codes.Code{codes.NotFound, codes.InvalidArgument, codes.PermissionDenied, codes.Unauthenticated, codes.Canceled} {
		t.Run(code.String(), func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			cfg.FailureThreshold = 1
			interceptor := UnaryClient("Profile", cfg, nil)
			for range 8 {
				err := interceptor(context.Background(), "/profile/Check", nil, nil, nil, func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
					return status.Error(code, "business result")
				})
				if status.Code(err) != code || errors.Is(err, ErrRejected) {
					t.Fatalf("call(%v) = %v; want unchanged business error", code, err)
				}
			}
		})
	}
	synctest.Test(t, func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.FailureThreshold = 1
		interceptor := UnaryClient("Location", cfg, nil)
		ctx, cancel := context.WithCancel(context.Background())
		err := interceptor(ctx, "/location/Get", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			cancel()
			return status.Error(codes.DeadlineExceeded, "parent expired")
		})
		if status.Code(err) != codes.DeadlineExceeded {
			t.Fatalf("call(parent canceled) = %v", err)
		}
		if err := interceptor(context.Background(), "/location/Get", nil, nil, nil, func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error { return nil }); err != nil {
			t.Fatalf("call(after parent cancellation) = %v; want closed breaker", err)
		}
	})
}
func TestTimeoutAndContextForwarding(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.FailureThreshold = 1
		interceptor := UnaryClient("Profile", cfg, nil)
		ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-actor-user-id", "actor"))
		start := time.Now()
		err := interceptor(ctx, "/profile/Check", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			md, _ := metadata.FromOutgoingContext(ctx)
			if md.Get("x-actor-user-id")[0] != "actor" {
				t.Error("metadata was lost")
			}
			<-ctx.Done()
			return status.FromContextError(ctx.Err()).Err()
		})
		if status.Code(err) != codes.DeadlineExceeded || time.Since(start) != 2*time.Second {
			t.Fatalf("call(timeout) = %v elapsed=%v; want deadline at 2s", err, time.Since(start))
		}
		if err := interceptor(context.Background(), "/profile/Check", nil, nil, nil, nil); !errors.Is(err, ErrRejected) {
			t.Fatalf("call(after timeout) = %v; want local rejection", err)
		}
	})
}
func TestFixedWindowAndDependencyIsolation(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.FailureThreshold = 2
		first, second := UnaryClient("Department", cfg, nil), UnaryClient("Profile", cfg, nil)
		invoke := func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
			return status.Error(codes.Unavailable, "offline")
		}
		_ = first(context.Background(), "get", nil, nil, nil, invoke)
		time.Sleep(31 * time.Second)
		if err := first(context.Background(), "get", nil, nil, nil, invoke); errors.Is(err, ErrRejected) {
			t.Fatalf("call(new window) = %v", err)
		}
		_ = first(context.Background(), "get", nil, nil, nil, invoke)
		if err := first(context.Background(), "get", nil, nil, nil, invoke); !errors.Is(err, ErrRejected) {
			t.Fatalf("call(open) = %v", err)
		}
		if err := second(context.Background(), "get", nil, nil, nil, invoke); errors.Is(err, ErrRejected) {
			t.Fatalf("call(independent dependency) = %v", err)
		}
	})
}
func TestConfigFromEnv(t *testing.T) {
	for _, key := range []string{"CIRCUIT_BREAKER_FAILURE_THRESHOLD", "CIRCUIT_BREAKER_INTERVAL", "CIRCUIT_BREAKER_OPEN_TIMEOUT", "CIRCUIT_BREAKER_CALL_TIMEOUT"} {
		t.Setenv(key, "")
	}
	if got, err := FromEnv(); err != nil || got != DefaultConfig() {
		t.Fatalf("FromEnv(defaults) = %+v, %v", got, err)
	}
	for _, key := range []string{"CIRCUIT_BREAKER_FAILURE_THRESHOLD", "CIRCUIT_BREAKER_INTERVAL", "CIRCUIT_BREAKER_OPEN_TIMEOUT", "CIRCUIT_BREAKER_CALL_TIMEOUT"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "0")
			if _, err := FromEnv(); err == nil {
				t.Errorf("FromEnv(%s=0) accepted invalid setting", key)
			}
		})
	}
}
