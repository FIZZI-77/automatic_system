package retry

import (
	"context"
	"strings"
	"time"

	"gateway/src/core/idempotency"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxAttempts = 3

func UnaryClientInterceptor(
	ctx context.Context,
	method string,
	req interface{},
	reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	if !shouldRetry(ctx, method) {
		return invoker(ctx, method, req, reply, cc, opts...)
	}

	var err error
	backoff := 50 * time.Millisecond
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = invoker(ctx, method, req, reply, cc, opts...)
		if err == nil || !isRetryable(err) || attempt == maxAttempts {
			return err
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}

		backoff *= 2
	}

	return err
}

func shouldRetry(ctx context.Context, method string) bool {
	if isReadOnlyMethod(method) {
		return true
	}

	_, hasIdempotencyKey := idempotency.FromContext(ctx)
	return hasIdempotencyKey && isIdempotentMutation(method)
}

func isReadOnlyMethod(method string) bool {
	parts := strings.Split(method, "/")
	name := parts[len(parts)-1]

	return strings.HasPrefix(name, "Get") ||
		strings.HasPrefix(name, "List")
}

func isIdempotentMutation(method string) bool {
	parts := strings.Split(method, "/")
	name := parts[len(parts)-1]

	switch name {
	case "Register",
		"ChangePassword",
		"SendVerificationEmail",
		"RequestPasswordReset",
		"ResetPassword",
		"CreateTicket",
		"UpdateTicket",
		"ChangeTicketStatus",
		"AssignBrigade",
		"CancelTicket",
		"CompleteTicket",
		"CreateDepartment",
		"UpdateDepartment",
		"DeleteDepartment":
		return true
	default:
		return false
	}
}

func isRetryable(err error) bool {
	code := status.Code(err)
	return code == codes.Unavailable ||
		code == codes.DeadlineExceeded ||
		code == codes.ResourceExhausted ||
		code == codes.Aborted
}
