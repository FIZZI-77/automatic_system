package handler

import (
	"context"
	"testing"

	"dispatch/models"

	dispatchv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/dispatch/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestAuthorize(t *testing.T) {
	allowed := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-actor-roles", "user,dispatcher"))
	if err := authorize(allowed); err != nil {
		t.Fatalf("dispatcher must be authorized: %v", err)
	}
	denied := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-actor-roles", "user"))
	if code := status.Code(authorize(denied)); code != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", code)
	}
}

func TestDispatchStatusMappings(t *testing.T) {
	values := []models.Status{models.StatusPending, models.StatusReserved, models.StatusConfirming, models.StatusAssigned, models.StatusFailed, models.StatusCancelled, models.StatusExpired}
	for _, value := range values {
		protoValue := statusToProto(value)
		restored, ok := statusFromProto(protoValue)
		if !ok || restored != value {
			t.Fatalf("round trip failed for %s", value)
		}
	}
	if _, ok := statusFromProto(dispatchv1.DispatchStatus_DISPATCH_STATUS_UNSPECIFIED); ok {
		t.Fatal("unspecified status must be rejected")
	}
}

func TestToProtoIncludesConcurrencyFields(t *testing.T) {
	op := &models.Operation{ID: uuid.New(), TicketID: uuid.New(), Mode: models.ModeManual, Status: models.StatusReserved, Version: 2, RequestedBy: uuid.New()}
	result := toProto(op)
	if result.GetVersion() != 2 || result.GetMode() != dispatchv1.DispatchMode_DISPATCH_MODE_MANUAL || result.GetStatus() != dispatchv1.DispatchStatus_DISPATCH_STATUS_RESERVED {
		t.Fatalf("unexpected mapping: %+v", result)
	}
}
