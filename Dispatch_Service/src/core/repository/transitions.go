package repository

import (
	"context"

	"dispatch/models"

	"github.com/google/uuid"
)

func (r *Repository) BeginConfirm(ctx context.Context, id, routeID uuid.UUID, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status='RESERVED'", `route_id=$3,status='CONFIRMING',version=version+1,updated_at=now()`, routeID)
}

func (r *Repository) FinishConfirm(ctx context.Context, id uuid.UUID, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status='CONFIRMING'", `status='ASSIGNED',version=version+1,updated_at=now()`)
}

func (r *Repository) SetFailed(ctx context.Context, id uuid.UUID, reason string, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status IN ('PENDING','RESERVED','CONFIRMING')", `status='FAILED',failure_reason=$3,version=version+1,updated_at=now()`, nullable(reason))
}
