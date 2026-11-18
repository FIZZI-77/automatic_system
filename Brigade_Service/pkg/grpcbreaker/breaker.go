// Package grpcbreaker ограничивает длительность gRPC-вызовов и изолирует отказы зависимостей.
package grpcbreaker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/sony/gobreaker/v2"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrRejected обозначает локальный отказ без сетевого обращения к зависимости.
var ErrRejected = errors.New("dependency circuit is open or probe is busy")

// Config задаёт параметры защиты одной зависимости для всех RPC её соединения.
type Config struct {
	FailureThreshold uint32
	Interval         time.Duration
	OpenTimeout      time.Duration
	CallTimeout      time.Duration
}

// DefaultConfig задаёт открытие цепи после пяти последовательных сбоев доступности в фиксированном окне 30 секунд.
func DefaultConfig() Config {
	return Config{FailureThreshold: 5, Interval: 30 * time.Second, OpenTimeout: time.Minute, CallTimeout: 2 * time.Second}
}

// FromEnv читает настройки CIRCUIT_BREAKER_* и отклоняет неверные значения при запуске.
func FromEnv() (Config, error) {
	c := DefaultConfig()
	if raw := os.Getenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD"); raw != "" {
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || n == 0 {
			return c, fmt.Errorf("CIRCUIT_BREAKER_FAILURE_THRESHOLD must be a positive uint32")
		}
		c.FailureThreshold = uint32(n)
	}
	for key, target := range map[string]*time.Duration{
		"CIRCUIT_BREAKER_INTERVAL":     &c.Interval,
		"CIRCUIT_BREAKER_OPEN_TIMEOUT": &c.OpenTimeout,
		"CIRCUIT_BREAKER_CALL_TIMEOUT": &c.CallTimeout,
	} {
		if raw := os.Getenv(key); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil || d <= 0 {
				return c, fmt.Errorf("%s must be a positive duration", key)
			}
			*target = d
		}
	}
	return c, nil
}

// IsAvailabilityError распознаёт сбои доступности, исключая ошибки валидации, прав, отсутствия записи и отмену запроса.
func IsAvailabilityError(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
		return true
	default:
		return errors.Is(err, context.DeadlineExceeded)
	}
}

type rejection struct {
	name  string
	cause error
}

func (e *rejection) Error() string              { return fmt.Sprintf("%s: %v", e.name, e.cause) }
func (e *rejection) Unwrap() error              { return ErrRejected }
func (e *rejection) GRPCStatus() *status.Status { return status.New(codes.Unavailable, e.Error()) }

// UnaryClient создаёт защиту один раз на соединение с зависимостью.
// Бизнес-ошибки подтверждают доступность сервиса и сбрасывают последовательность сбоев.
// Отмена родительского контекста не считается сбоем зависимости.
func UnaryClient(name string, cfg Config, logger *zap.Logger) grpc.UnaryClientInterceptor {
	if logger == nil {
		logger = zap.NewNop()
	}
	defaults := DefaultConfig()
	if cfg.FailureThreshold == 0 {
		cfg.FailureThreshold = defaults.FailureThreshold
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaults.Interval
	}
	if cfg.OpenTimeout <= 0 {
		cfg.OpenTimeout = defaults.OpenTimeout
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = defaults.CallTimeout
	}
	cb := gobreaker.NewCircuitBreaker[struct{}](gobreaker.Settings{
		Name: name, MaxRequests: 1, Interval: cfg.Interval, Timeout: cfg.OpenTimeout,
		ReadyToTrip:  func(c gobreaker.Counts) bool { return c.ConsecutiveFailures >= cfg.FailureThreshold },
		IsSuccessful: func(err error) bool { return !IsAvailabilityError(err) },
		OnStateChange: func(name string, from, to gobreaker.State) {
			logger.Warn("dependency circuit changed", zap.String("dependency", name), zap.String("from", from.String()), zap.String("to", to.String()))
		},
	})
	return func(ctx context.Context, method string, request, reply any, connection *grpc.ClientConn, invoke grpc.UnaryInvoker, options ...grpc.CallOption) error {
		if err := ctx.Err(); err != nil {
			return status.FromContextError(err).Err()
		}
		var callErr error
		_, err := cb.Execute(func() (struct{}, error) {
			callCtx, cancel := context.WithTimeout(ctx, cfg.CallTimeout)
			defer cancel()
			callErr = invoke(callCtx, method, request, reply, connection, options...)
			if ctx.Err() != nil {
				return struct{}{}, nil
			}
			return struct{}{}, callErr
		})
		if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
			return &rejection{name: name, cause: err}
		}
		return callErr
	}
}
