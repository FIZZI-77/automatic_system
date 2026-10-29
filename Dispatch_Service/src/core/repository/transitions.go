package repository

import (
	"context"

	"dispatch/models"

	"github.com/google/uuid"
)

// BeginConfirm переводит RESERVED в CONFIRMING с сохранением маршрута и события
// dispatch.route_built. Несовпадение версии expected или статуса даёт ErrConflict.
func (r *Repository) BeginConfirm(ctx context.Context, id, routeID uuid.UUID, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status='RESERVED'", `route_id=$3,status='CONFIRMING',version=version+1,updated_at=now()`, "dispatch.route_built", nil, routeID)
}

// FinishConfirm переводит CONFIRMING в ASSIGNED с событием outbox и увеличением версии.
// Отсутствие записи, неверная версия expected или статус дают ErrConflict.
func (r *Repository) FinishConfirm(ctx context.Context, id uuid.UUID, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status='CONFIRMING'", `status='ASSIGNED',version=version+1,updated_at=now()`, "dispatch.assigned", nil)
}

// SetFailed переводит PENDING, RESERVED или CONFIRMING в FAILED с этапом, кодом,
// причиной и событием outbox. Несовпадение версии expected или статуса даёт ErrConflict.
func (r *Repository) SetFailed(ctx context.Context, id uuid.UUID, stage, code, reason string, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status IN ('PENDING','RESERVED','CONFIRMING')", `status='FAILED',failure_stage=$3,failure_code=$4,failure_reason=$5,version=version+1,updated_at=now()`, "dispatch.failed", nil, stage, code, nullable(reason))
}
