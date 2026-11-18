package handler

import (
	"context"
	"testing"

	filev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/file/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestPublicLinkRejectsResourceForgeryBeforeStorage(t *testing.T) {
	h := New(nil, nil, "private-report-token")
	for _, roles := range [][]string{{"user"}, {"worker"}, {"dispatcher"}} {
		_, err := h.LinkFile(context.Background(), &filev1.LinkFileRequest{ActorRoles: roles, ResourceType: "work_report", ResourceId: "victim"})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("LinkFile roles %v = %v, want PermissionDenied", roles, err)
		}
	}
	for _, token := range []string{"", "wrong", "private-report-token"} {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-report-link-token", token))
		if got := h.canLink(ctx, []string{"worker"}); got != (token == "private-report-token") {
			t.Fatalf("report capability accepted=%v for valid=%v", got, token == "private-report-token")
		}
	}
	if !h.canLink(context.Background(), []string{"admin"}) {
		t.Fatal("admin linking unexpectedly rejected")
	}
	if New(nil, nil, "").canLink(metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-report-link-token", "")), nil) {
		t.Fatal("empty configured capability accepted")
	}
}
