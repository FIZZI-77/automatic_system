package handler

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
)

func TestTicketErrorCode_ContextErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{
			name: "deadline exceeded",
			err:  fmt.Errorf("repository query: %w", context.DeadlineExceeded),
			want: codes.DeadlineExceeded,
		},
		{
			name: "canceled",
			err:  fmt.Errorf("repository query: %w", context.Canceled),
			want: codes.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := ticketErrorCode(tt.err); got != tt.want {
				t.Fatalf("ticketErrorCode() = %s, want %s", got, tt.want)
			}
		})
	}
}
