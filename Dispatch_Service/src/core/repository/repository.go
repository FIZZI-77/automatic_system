package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"dispatch/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	writeDB *pgxpool.Pool
	readDB  *pgxpool.Pool
	lockDB  *pgxpool.Pool
}
type scanner interface{ Scan(...any) error }

func New(writeDB, readDB *pgxpool.Pool) *Repository {
	return NewWithLockPool(writeDB, readDB, writeDB)
}

// NewWithLockPool creates a repository with a dedicated pool for session-level advisory locks.
func NewWithLockPool(writeDB, readDB, lockDB *pgxpool.Pool) *Repository {
	return &Repository{writeDB: writeDB, readDB: readDB, lockDB: lockDB}
}

func (r *Repository) Create(ctx context.Context, input models.CreateOperationInput) (*models.Operation, error) {
	op := &models.Operation{
		ID:           uuid.New(),
		TicketID:     input.TicketID,
		DepartmentID: &input.DepartmentID,
		CategoryID:   &input.CategoryID,
		Priority:     input.Priority,
		Mode:         input.Mode,
		Status:       models.StatusPending,
		Version:      1,
		RequestedBy:  input.RequestedBy,
		ExpiresAt:    time.Now().UTC().Add(input.TTL),
	}
	tx, err := r.writeDB.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create dispatch operation: %w", err)
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `INSERT INTO dispatch_operations(id,ticket_id,department_id,category_id,priority,mode,status,version,requested_by,expires_at,trigger_event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING created_at,updated_at`, op.ID, op.TicketID, op.DepartmentID, op.CategoryID, op.Priority, op.Mode, op.Status, op.Version, op.RequestedBy, op.ExpiresAt, input.TriggerEventID).Scan(&op.CreatedAt, &op.UpdatedAt)
	if err != nil {
		var dbErr *pgconn.PgError
		if errors.As(err, &dbErr) && dbErr.Code == "23505" {
			if input.TriggerEventID != nil {
				if rollbackErr := tx.Rollback(ctx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
					return nil, fmt.Errorf("rollback duplicate dispatch operation: %w", rollbackErr)
				}
				existing, lookupErr := scan(r.writeDB.QueryRow(ctx, baseSelect+` WHERE trigger_event_id=$1`, *input.TriggerEventID))
				if lookupErr == nil {
					return existing, nil
				}
				if !errors.Is(lookupErr, pgx.ErrNoRows) {
					return nil, fmt.Errorf("lookup dispatch trigger event: %w", lookupErr)
				}
			}
			return nil, models.ErrConflict
		}
		return nil, fmt.Errorf("create dispatch operation: %w", err)
	}
	if err = appendOperationEvent(ctx, tx, "dispatch.requested", op, nil); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create dispatch operation: %w", err)
	}
	return op, nil
}

// TryOperationLock acquires cross-replica ownership of an automatic dispatch workflow.
func (r *Repository) TryOperationLock(ctx context.Context, operationID uuid.UUID) (func() error, bool, error) {
	connection, err := r.lockDB.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("acquire dispatch operation lock connection: %w", err)
	}
	transaction, err := connection.Begin(ctx)
	if err != nil {
		connection.Release()
		return nil, false, fmt.Errorf("begin dispatch operation lock: %w", err)
	}
	var acquired bool
	if err = transaction.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))`, operationID.String()).Scan(&acquired); err != nil {
		rollbackErr := transaction.Rollback(ctx)
		connection.Release()
		return nil, false, errors.Join(fmt.Errorf("acquire dispatch operation lock: %w", err), rollbackErr)
	}
	if !acquired {
		rollbackErr := transaction.Rollback(ctx)
		connection.Release()
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			return nil, false, fmt.Errorf("rollback unclaimed dispatch operation lock: %w", rollbackErr)
		}
		return func() error { return nil }, false, nil
	}
	var once sync.Once
	var releaseErr error
	release := func() error {
		once.Do(func() {
			// Rollback must run after request cancellation so PgBouncer releases the pinned backend.
			unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			releaseErr = transaction.Rollback(unlockCtx)
			connection.Release()
			if errors.Is(releaseErr, pgx.ErrTxClosed) {
				releaseErr = nil
			}
		})
		return releaseErr
	}
	return release, true, nil
}
func (r *Repository) Get(ctx context.Context, id uuid.UUID) (*models.Operation, error) {
	op, err := scan(r.readDB.QueryRow(ctx, baseSelect+` WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	return op, err
}

func (r *Repository) GetByTriggerEvent(ctx context.Context, eventID uuid.UUID) (*models.Operation, error) {
	op, err := scan(r.writeDB.QueryRow(ctx, baseSelect+` WHERE trigger_event_id=$1`, eventID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	return op, err
}
func (r *Repository) SetReserved(ctx context.Context, id, brigadeID uuid.UUID, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status='PENDING'", `brigade_id=$3,status='RESERVED',version=version+1,updated_at=now()`, "dispatch.reserved", nil, brigadeID)
}
func (r *Repository) SetAssigned(ctx context.Context, id, routeID uuid.UUID, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status='RESERVED'", `route_id=$3,status='ASSIGNED',version=version+1,updated_at=now()`, "dispatch.assigned", nil, routeID)
}
func (r *Repository) SetTerminal(ctx context.Context, id uuid.UUID, status models.Status, reason string, expected int32) (*models.Operation, error) {
	eventType := "dispatch.canceled"
	failureCode := "CANCELED_BY_USER"
	failureStage := "USER_CANCELLATION"
	if status == models.StatusExpired {
		eventType = "dispatch.expired"
		failureCode = "RESERVATION_EXPIRED"
		failureStage = "RESERVATION"
	}
	return r.transition(ctx, id, expected, "status IN ('PENDING','RESERVED')", `status=$3,failure_code=$4,failure_stage=$5,failure_reason=$6,version=version+1,updated_at=now()`, eventType, nil, status, failureCode, failureStage, nullable(reason))
}
func (r *Repository) transition(ctx context.Context, id uuid.UUID, expected int32, guard, set, eventType string, extra map[string]any, args ...any) (*models.Operation, error) {
	values := []any{id, expected}
	values = append(values, args...)
	tx, err := r.writeDB.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin dispatch transition: %w", err)
	}
	defer tx.Rollback(ctx)
	op, err := scan(tx.QueryRow(ctx, baseSelectUpdate+set+` WHERE id=$1 AND version=$2 AND `+guard+returning, values...))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrConflict
	}
	if err != nil {
		return nil, fmt.Errorf("update dispatch transition: %w", err)
	}
	if err = appendOperationEvent(ctx, tx, eventType, op, extra); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit dispatch transition: %w", err)
	}
	return op, nil
}
func (r *Repository) List(ctx context.Context, in *models.ListInput) ([]*models.Operation, int64, error) {
	where := []string{"TRUE"}
	args := make([]any, 0, 5)
	add := func(column string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(column, len(args)))
	}
	if in.TicketID != nil {
		add("ticket_id=$%d", *in.TicketID)
	}
	if in.BrigadeID != nil {
		add("brigade_id=$%d", *in.BrigadeID)
	}
	if in.Status != nil {
		add("status=$%d", *in.Status)
	}
	clause := strings.Join(where, " AND ")
	var total int64
	if err := r.readDB.QueryRow(ctx, "SELECT count(*) FROM dispatch_operations WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, in.Limit, in.Offset)
	rows, err := r.readDB.Query(ctx, baseSelect+" WHERE "+clause+fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := make([]*models.Operation, 0, in.Limit)
	for rows.Next() {
		item, scanErr := scan(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		result = append(result, item)
	}
	return result, total, rows.Err()
}
func (r *Repository) Expire(ctx context.Context, limit int) ([]*models.Operation, error) {
	if limit <= 0 {
		limit = 100
	}
	tx, err := r.writeDB.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin expire dispatch operations: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `WITH claimed AS (
		SELECT id FROM dispatch_operations
		WHERE status IN ('PENDING','RESERVED','CONFIRMING') AND expires_at<=now()
		ORDER BY expires_at, id FOR UPDATE SKIP LOCKED LIMIT $1
	)
	UPDATE dispatch_operations AS operation
	SET status='EXPIRED',failure_code='RESERVATION_EXPIRED',failure_stage='RESERVATION',failure_reason='dispatch operation expired',version=operation.version+1,updated_at=now()
	FROM claimed WHERE operation.id=claimed.id
	RETURNING operation.id,operation.ticket_id,operation.department_id,operation.category_id,operation.priority,operation.brigade_id,operation.route_id,operation.mode,operation.status,operation.version,operation.requested_by,operation.failure_code,operation.failure_stage,operation.failure_reason,operation.expires_at,operation.created_at,operation.updated_at`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]*models.Operation, 0)
	for rows.Next() {
		item, scanErr := scan(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	for _, item := range result {
		if err = appendOperationEvent(ctx, tx, "dispatch.expired", item, nil); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit expired dispatch operations: %w", err)
	}
	return result, nil
}
func scan(row scanner) (*models.Operation, error) {
	op := new(models.Operation)
	err := row.Scan(&op.ID, &op.TicketID, &op.DepartmentID, &op.CategoryID, &op.Priority, &op.BrigadeID, &op.RouteID, &op.Mode, &op.Status, &op.Version, &op.RequestedBy, &op.FailureCode, &op.FailureStage, &op.FailureReason, &op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return op, nil
}
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

const baseSelect = `SELECT id,ticket_id,department_id,category_id,priority,brigade_id,route_id,mode,status,version,requested_by,failure_code,failure_stage,failure_reason,expires_at,created_at,updated_at FROM dispatch_operations`
const baseSelectUpdate = `UPDATE dispatch_operations SET `
const returning = ` RETURNING id,ticket_id,department_id,category_id,priority,brigade_id,route_id,mode,status,version,requested_by,failure_code,failure_stage,failure_reason,expires_at,created_at,updated_at`
