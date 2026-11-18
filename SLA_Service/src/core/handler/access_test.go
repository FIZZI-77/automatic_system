package handler

import (
	"context"
	"fmt"
	"testing"

	slav1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/sla/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"sla/models"
)

func TestSLARoleAccess(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		roles                string
		adminCode, staffCode codes.Code
	}{
		{"", codes.PermissionDenied, codes.PermissionDenied}, {"user", codes.PermissionDenied, codes.PermissionDenied},
		{"worker", codes.PermissionDenied, codes.OK}, {"dispatcher", codes.PermissionDenied, codes.OK}, {"worker, ADMIN ", codes.OK, codes.OK},
	} {
		t.Run(tt.roles, func(t *testing.T) {
			t.Parallel()
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-actor-roles", tt.roles))
			if got := status.Code(admin(ctx)); got != tt.adminCode {
				t.Errorf("admin(%q) = %v; want %v", tt.roles, got, tt.adminCode)
			}
			if got := status.Code(staff(ctx)); got != tt.staffCode {
				t.Errorf("staff(%q) = %v; want %v", tt.roles, got, tt.staffCode)
			}
			if tt.adminCode != codes.OK {
				if _, err := New(nil).CreateRule(ctx, &slav1.CreateRuleRequest{}); status.Code(err) != tt.adminCode {
					t.Fatalf("CreateRule unauthorized = %v; want %v", err, tt.adminCode)
				}
			}
		})
	}
}
func TestSLAErrorMapping(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		err  error
		want codes.Code
	}{
		{nil, codes.OK}, {fmt.Errorf("wrapped: %w", models.ErrNotFound), codes.NotFound}, {models.ErrConflict, codes.AlreadyExists}, {models.ErrInvalidArgument, codes.InvalidArgument}, {context.Canceled, codes.Unavailable},
	} {
		if got := status.Code(mapped(tt.err)); got != tt.want {
			t.Errorf("mapped(%v) = %v; want %v", tt.err, got, tt.want)
		}
	}
}
