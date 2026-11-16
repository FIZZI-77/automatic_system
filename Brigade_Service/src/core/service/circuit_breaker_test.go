package service

import (
	"brigade/models"
	"brigade/pkg/grpcbreaker"
	"context"
	"errors"
	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
	"testing/synctest"
	"time"
)

func TestDepartmentOpenCircuitDoesNotRetry(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		cfg := grpcbreaker.DefaultConfig()
		cfg.FailureThreshold = 1
		interceptor := grpcbreaker.UnaryClient("Department", cfg, nil)
		_ = interceptor(context.Background(), "get", nil, nil, nil, func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
			return status.Error(codes.Unavailable, "offline")
		})
		rejection := interceptor(context.Background(), "get", nil, nil, nil, nil)
		calls := 0
		client := &mockDepartmentClient{getDepartmentByIDFunc: func(context.Context, *departmentv1.GetDepartmentByIDRequest, ...grpc.CallOption) (*departmentv1.GetDepartmentByIDResponse, error) {
			calls++
			return nil, rejection
		}}
		start := time.Now()
		_, err := NewBrigadeService(nil, client, zap.NewNop()).getDepartmentByIDWithRetry(context.Background(), zap.NewNop(), uuid.New())
		if !errors.Is(err, models.ErrDependencyUnavailable) || calls != 1 || time.Since(start) != 0 {
			t.Fatalf("getDepartmentByIDWithRetry(open) = %v calls=%d elapsed=%v; want unavailable without retries", err, calls, time.Since(start))
		}
	})
}

func TestDepartmentTimeoutOpensCircuit(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		cfg := grpcbreaker.DefaultConfig()
		cfg.FailureThreshold = 1
		interceptor := grpcbreaker.UnaryClient("Department", cfg, nil)
		networkCalls := 0
		client := &mockDepartmentClient{getDepartmentByIDFunc: func(ctx context.Context, _ *departmentv1.GetDepartmentByIDRequest, _ ...grpc.CallOption) (*departmentv1.GetDepartmentByIDResponse, error) {
			err := interceptor(ctx, "get", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
				networkCalls++
				<-ctx.Done()
				return status.FromContextError(ctx.Err()).Err()
			})
			return nil, err
		}}
		start := time.Now()
		_, err := NewBrigadeService(nil, client, zap.NewNop()).getDepartmentByIDWithRetry(context.Background(), zap.NewNop(), uuid.New())
		if !errors.Is(err, models.ErrDependencyUnavailable) || networkCalls != 1 || time.Since(start) > 2200*time.Millisecond {
			t.Fatalf("getDepartmentByIDWithRetry(timeout) = %v network calls=%d elapsed=%v; want one bounded network call", err, networkCalls, time.Since(start))
		}
	})
}
