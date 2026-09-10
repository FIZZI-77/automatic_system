package repository

import (
	"context"
	"testing"
	"time"

	"dispatch/models"

	"github.com/google/uuid"
)

func TestOperationEventPayloadContracts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	brigadeID, routeID := uuid.New(), uuid.New()
	departmentID, categoryID := uuid.New(), uuid.New()
	failureCode, failureStage, failureReason := "NO_ROUTE", "ROUTING", "route unavailable"
	operation := &models.Operation{
		ID: uuid.New(), TicketID: uuid.New(), DepartmentID: &departmentID, CategoryID: &categoryID,
		Priority: "EMERGENCY", BrigadeID: &brigadeID, RouteID: &routeID,
		Mode: models.ModeAutomatic, Status: models.StatusFailed,
		FailureCode: &failureCode, FailureStage: &failureStage, FailureReason: &failureReason,
		CreatedAt: now.Add(-time.Minute), UpdatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	tests := []struct {
		eventType, timestamp string
	}{
		{eventType: "dispatch.requested"},
		{eventType: "dispatch.reserved", timestamp: "reserved_at"},
		{eventType: "dispatch.route_built", timestamp: "route_built_at"},
		{eventType: "dispatch.assigned", timestamp: "assigned_at"},
		{eventType: "dispatch.failed", timestamp: "failed_at"},
		{eventType: "dispatch.expired", timestamp: "expired_at"},
		{eventType: "dispatch.canceled", timestamp: "canceled_at"},
	}
	for _, test := range tests {
		t.Run(test.eventType, func(t *testing.T) {
			eventID := uuid.New()
			payload := operationEventPayload(context.Background(), eventID, test.eventType, operation)
			assertDispatchEnvelope(t, payload, eventID, test.eventType, operation)
			if test.timestamp != "" {
				if got, ok := payload[test.timestamp].(time.Time); !ok || !got.Equal(now) {
					t.Errorf("%s = %v, want %v", test.timestamp, payload[test.timestamp], now)
				}
			}
		})
	}
}

func TestCandidateEventPayloadContract(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	departmentID, categoryID := uuid.New(), uuid.New()
	operation := &models.Operation{
		ID: uuid.New(), TicketID: uuid.New(), DepartmentID: &departmentID, CategoryID: &categoryID,
		Priority: "HIGH", Mode: models.ModeAutomatic, CreatedAt: now.Add(-time.Minute),
	}
	eventID := uuid.New()
	payload := candidateEventPayload(context.Background(), eventID, operation, 5, 3, now)
	assertDispatchEnvelope(t, payload, eventID, "dispatch.candidates_ranked", operation)
	if payload["candidate_count"] != 5 || payload["reachable_candidate_count"] != 3 {
		t.Errorf("candidate counts = (%v,%v), want (5,3)", payload["candidate_count"], payload["reachable_candidate_count"])
	}
}

func assertDispatchEnvelope(t *testing.T, payload map[string]any, eventID uuid.UUID, eventType string, operation *models.Operation) {
	t.Helper()
	want := map[string]any{
		"event_id": eventID, "event_type": eventType, "event_version": dispatchEventVersion,
		"producer": "dispatch-service", "operation_id": operation.ID, "ticket_id": operation.TicketID,
		"department_id": operation.DepartmentID, "category_id": operation.CategoryID,
		"priority": operation.Priority, "mode": operation.Mode,
	}
	for key, expected := range want {
		if payload[key] != expected {
			t.Errorf("%s = %v, want %v", key, payload[key], expected)
		}
	}
	if _, ok := payload["occurred_at"].(time.Time); !ok {
		t.Errorf("occurred_at = %T, want time.Time", payload["occurred_at"])
	}
	if _, ok := payload["trace_id"]; !ok {
		t.Error("trace_id is missing")
	}
}
