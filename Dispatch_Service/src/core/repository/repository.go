package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"dispatch/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct{ db *pgxpool.Pool }
type scanner interface{ Scan(...any) error }

func New(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

func (r *Repository) Create(ctx context.Context, ticketID, requestedBy uuid.UUID, mode models.Mode, ttl time.Duration) (*models.Operation, error) {
	op := &models.Operation{ID: uuid.New(), TicketID: ticketID, Mode: mode, Status: models.StatusPending, Version: 1, RequestedBy: requestedBy, ExpiresAt: time.Now().UTC().Add(ttl)}
	err := r.db.QueryRow(ctx, `INSERT INTO dispatch_operations(id,ticket_id,mode,status,version,requested_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at,updated_at`, op.ID, op.TicketID, op.Mode, op.Status, op.Version, op.RequestedBy, op.ExpiresAt).Scan(&op.CreatedAt, &op.UpdatedAt)
	if err != nil {
		var dbErr *pgconn.PgError
		if errors.As(err, &dbErr) && dbErr.Code == "23505" {
			return nil, models.ErrConflict
		}
		return nil, fmt.Errorf("create dispatch operation: %w", err)
	}
	return op, nil
}
func (r *Repository) Get(ctx context.Context, id uuid.UUID) (*models.Operation, error) {
	op, err := scan(r.db.QueryRow(ctx, baseSelect+` WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	return op, err
}
func (r *Repository) SetReserved(ctx context.Context, id, brigadeID uuid.UUID, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status='PENDING'", `brigade_id=$3,status='RESERVED',version=version+1,updated_at=now()`, brigadeID)
}
func (r *Repository) SetAssigned(ctx context.Context, id, routeID uuid.UUID, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status='RESERVED'", `route_id=$3,status='ASSIGNED',version=version+1,updated_at=now()`, routeID)
}
func (r *Repository) SetTerminal(ctx context.Context, id uuid.UUID, status models.Status, reason string, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status IN ('PENDING','RESERVED')", `status=$3,failure_reason=$4,version=version+1,updated_at=now()`, status, nullable(reason))
}
func (r *Repository) transition(ctx context.Context, id uuid.UUID, expected int32, guard, set string, args ...any) (*models.Operation, error) {
	values := []any{id, expected}
	values = append(values, args...)
	op, err := scan(r.db.QueryRow(ctx, baseSelectUpdate+set+` WHERE id=$1 AND version=$2 AND `+guard+returning, values...))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrConflict
	}
	return op, err
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
	if err := r.db.QueryRow(ctx, "SELECT count(*) FROM dispatch_operations WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, in.Limit, in.Offset)
	rows, err := r.db.Query(ctx, baseSelect+" WHERE "+clause+fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
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
func (r *Repository) Expire(ctx context.Context) ([]*models.Operation, error) {
	rows, err := r.db.Query(ctx, baseSelectUpdate+`status='EXPIRED',failure_reason='reservation expired',version=version+1,updated_at=now() WHERE status='RESERVED' AND expires_at<=now()`+returning)
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
	return result, rows.Err()
}
func scan(row scanner) (*models.Operation, error) {
	op := new(models.Operation)
	err := row.Scan(&op.ID, &op.TicketID, &op.BrigadeID, &op.RouteID, &op.Mode, &op.Status, &op.Version, &op.RequestedBy, &op.FailureReason, &op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt)
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

const baseSelect = `SELECT id,ticket_id,brigade_id,route_id,mode,status,version,requested_by,failure_reason,expires_at,created_at,updated_at FROM dispatch_operations`
const baseSelectUpdate = `UPDATE dispatch_operations SET `
const returning = ` RETURNING id,ticket_id,brigade_id,route_id,mode,status,version,requested_by,failure_reason,expires_at,created_at,updated_at`
