package repository

import (
	"context"
	"fmt"

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
	return r.transition(ctx, id, expected, "status IN ('PENDING','RESERVED','CONFIRMING')", `status='FAILED',failure_stage=$3,failure_code=$4,failure_reason=$5,release_pending=(brigade_id IS NOT NULL),release_actor_id=requested_by,version=version+1,updated_at=now()`, "dispatch.failed", nil, stage, code, nullable(reason))
}

// Cancel сохраняет отмену и необходимость освобождения резерва в одной транзакции с outbox.
func (r *Repository) Cancel(ctx context.Context, id, actor uuid.UUID, reason string, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status IN ('PENDING','RESERVED')", `status='CANCELLED',failure_code='CANCELED_BY_USER',failure_stage='USER_CANCELLATION',failure_reason=$3,release_pending=(brigade_id IS NOT NULL),release_actor_id=$4,version=version+1,updated_at=now()`, "dispatch.canceled", nil, nullable(reason), actor)
}

// CompleteRelease снимает внутреннюю блокировку ресурса после успешной компенсации.
// Версию публичной операции не меняет; повторное подтверждение безопасно.
func (r *Repository) CompleteRelease(ctx context.Context, id uuid.UUID) error {
	_, err := r.writeDB.Exec(ctx, `UPDATE dispatch_operations SET release_pending=false,release_actor_id=NULL,updated_at=now() WHERE id=$1 AND release_pending`, id)
	if err != nil {
		return fmt.Errorf("complete dispatch release: %w", err)
	}
	return nil
}

// DeferRelease переносит неудачную компенсацию в конец очереди обработки.
func (r *Repository) DeferRelease(ctx context.Context, id uuid.UUID) error {
	_, err := r.writeDB.Exec(ctx, `UPDATE dispatch_operations SET updated_at=clock_timestamp() WHERE id=$1 AND release_pending`, id)
	return err
}
