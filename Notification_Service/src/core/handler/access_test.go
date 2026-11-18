package handler

import (
	"context"
	"fmt"
	"testing"

	notificationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/notification/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"notification/models"
	"notification/src/core/service"
)

func TestNotificationAccess(t *testing.T) {
	t.Parallel()
	owner := uuid.New()
	other := uuid.New()
	for _, tt := range []struct {
		name, actor, target, roles string
		want                       codes.Code
	}{
		{"owner", owner.String(), owner.String(), "user", codes.OK},
		{"stranger", other.String(), owner.String(), "user", codes.PermissionDenied},
		{"admin", other.String(), owner.String(), "worker, ADMIN ", codes.OK},
		{"missing actor", "", owner.String(), "", codes.PermissionDenied},
		{"invalid target", owner.String(), "broken", "admin", codes.InvalidArgument},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-actor-user-id", tt.actor, "x-actor-roles", tt.roles))
			got, err := self(ctx, tt.target)
			if status.Code(err) != tt.want || (tt.want == codes.OK && got.String() != tt.target) {
				t.Fatalf("self(%q) = %v, %v; want code %v", tt.target, got, err, tt.want)
			}
			if tt.want != codes.OK {
				if _, err := New(nil).ListNotifications(ctx, &notificationv1.ListNotificationsRequest{UserId: tt.target}); status.Code(err) != tt.want {
					t.Fatalf("ListNotifications unauthorized = %v; want %v", err, tt.want)
				}
			}
		})
	}
}
func TestNotificationErrorMapping(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		err  error
		want codes.Code
	}{{nil, codes.OK}, {fmt.Errorf("wrapped: %w", service.ErrNotFound), codes.NotFound}, {context.Canceled, codes.FailedPrecondition}} {
		if got := status.Code(mapped(tt.err)); got != tt.want {
			t.Errorf("mapped(%v) = %v; want %v", tt.err, got, tt.want)
		}
	}
	if note((*models.Notification)(nil)) != nil {
		t.Fatal("note(nil) should be nil")
	}
}
