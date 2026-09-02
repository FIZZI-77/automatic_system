package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"dispatch/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel/trace"
)

const dispatchEventVersion = 1

func appendOperationEvent(
	ctx context.Context,
	tx pgx.Tx,
	eventType string,
	operation *models.Operation,
	extra map[string]any,
) error {
	eventID := uuid.New()
	payload := operationEventPayload(ctx, eventID, eventType, operation)
	for key, value := range extra {
		payload[key] = value
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode dispatch event: %w", err)
	}
	if _, err = tx.Exec(
		ctx,
		`INSERT INTO dispatch_outbox_events(id,aggregate_id,event_type,payload) VALUES($1,$2,$3,$4)`,
		eventID,
		operation.ID,
		eventType,
		encoded,
	); err != nil {
		return fmt.Errorf("append dispatch event: %w", err)
	}
	return nil
}

func operationEventPayload(ctx context.Context, eventID uuid.UUID, eventType string, operation *models.Operation) map[string]any {
	payload := map[string]any{
		"event_id":       eventID,
		"event_type":     eventType,
		"event_version":  dispatchEventVersion,
		"producer":       "dispatch-service",
		"operation_id":   operation.ID,
		"ticket_id":      operation.TicketID,
		"department_id":  operation.DepartmentID,
		"category_id":    operation.CategoryID,
		"priority":       operation.Priority,
		"brigade_id":     operation.BrigadeID,
		"route_id":       operation.RouteID,
		"mode":           operation.Mode,
		"status":         operation.Status,
		"failure_code":   operation.FailureCode,
		"failure_stage":  operation.FailureStage,
		"failure_reason": operation.FailureReason,
		"requested_at":   operation.CreatedAt,
		"expires_at":     operation.ExpiresAt,
		"occurred_at":    operation.UpdatedAt,
		"trace_id":       traceID(ctx),
	}
	switch eventType {
	case "dispatch.reserved":
		payload["reserved_at"] = operation.UpdatedAt
	case "dispatch.route_built":
		payload["route_built_at"] = operation.UpdatedAt
	case "dispatch.assigned":
		payload["assigned_at"] = operation.UpdatedAt
	case "dispatch.failed":
		payload["failed_at"] = operation.UpdatedAt
	case "dispatch.expired":
		payload["expired_at"] = operation.UpdatedAt
	case "dispatch.canceled":
		payload["canceled_at"] = operation.UpdatedAt
	}
	return payload
}

func appendCandidateEvent(
	ctx context.Context,
	tx pgx.Tx,
	operation *models.Operation,
	candidateCount int,
	reachableCount int,
) error {
	now := time.Now().UTC()
	eventID := uuid.New()
	payload := candidateEventPayload(ctx, eventID, operation, candidateCount, reachableCount, now)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode candidate event: %w", err)
	}
	if _, err = tx.Exec(
		ctx,
		`INSERT INTO dispatch_outbox_events(id,aggregate_id,event_type,payload) VALUES($1,$2,$3,$4)`,
		eventID,
		operation.ID,
		"dispatch.candidates_ranked",
		encoded,
	); err != nil {
		return fmt.Errorf("append candidate event: %w", err)
	}
	return nil
}

func candidateEventPayload(
	ctx context.Context,
	eventID uuid.UUID,
	operation *models.Operation,
	candidateCount, reachableCount int,
	occurredAt time.Time,
) map[string]any {
	return map[string]any{
		"event_id":                  eventID,
		"event_type":                "dispatch.candidates_ranked",
		"event_version":             dispatchEventVersion,
		"producer":                  "dispatch-service",
		"operation_id":              operation.ID,
		"ticket_id":                 operation.TicketID,
		"department_id":             operation.DepartmentID,
		"category_id":               operation.CategoryID,
		"priority":                  operation.Priority,
		"mode":                      operation.Mode,
		"requested_at":              operation.CreatedAt,
		"candidate_count":           candidateCount,
		"reachable_candidate_count": reachableCount,
		"occurred_at":               occurredAt,
		"trace_id":                  traceID(ctx),
	}
}

func (r *Repository) RecordCandidates(
	ctx context.Context,
	operation *models.Operation,
	candidateCount int,
	reachableCount int,
) error {
	tx, err := r.writeDB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin candidate event: %w", err)
	}
	defer tx.Rollback(ctx)
	if err = appendCandidateEvent(ctx, tx, operation, candidateCount, reachableCount); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit candidate event: %w", err)
	}
	return nil
}

func traceID(ctx context.Context) string {
	spanContext := trace.SpanContextFromContext(ctx)
	if !spanContext.IsValid() {
		return ""
	}
	return spanContext.TraceID().String()
}
