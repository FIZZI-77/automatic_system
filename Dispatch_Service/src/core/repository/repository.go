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
type scanner interface {
	// Scan переносит значения строки в переданные указатели и возвращает ошибку чтения или преобразования.
	Scan(...any) error
}

// New создаёт хранилище диспетчеризации; блокировки операций используют пул записи.
func New(writeDB, readDB *pgxpool.Pool) *Repository {
	return NewWithLockPool(writeDB, readDB, writeDB)
}

// NewWithLockPool создаёт хранилище с отдельным пулом для длительно удерживаемых
// advisory-блокировок операций. Пулы чтения, записи и блокировок задаёт вызывающий код.
func NewWithLockPool(writeDB, readDB, lockDB *pgxpool.Pool) *Repository {
	return &Repository{writeDB: writeDB, readDB: readDB, lockDB: lockDB}
}

// Create транзакционно сохраняет операцию PENDING с версией 1, сроком действия TTL
// и событием dispatch.requested. Повтор trigger_event_id возвращает существующую
// операцию; прочее нарушение уникальности преобразуется в ErrConflict.
func (r *Repository) Create(ctx context.Context, input models.CreateOperationInput) (*models.Operation, error) {
	op := &models.Operation{
		ID:                uuid.New(),
		TicketID:          input.TicketID,
		DepartmentID:      &input.DepartmentID,
		CategoryID:        &input.CategoryID,
		Priority:          input.Priority,
		Mode:              input.Mode,
		Status:            models.StatusPending,
		Version:           1,
		RequestedBy:       input.RequestedBy,
		ExpiresAt:         time.Now().UTC().Add(input.TTL),
		AssignmentComment: input.AssignmentComment,
	}
	tx, err := r.writeDB.Begin(ctx)

	if err != nil {
		return nil, fmt.Errorf("begin create dispatch operation: %w", err)
	}

	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `INSERT INTO dispatch_operations(id,ticket_id,department_id,category_id,priority,mode,status,version,requested_by,expires_at,trigger_event_id,assignment_comment) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING created_at,updated_at`, op.ID, op.TicketID, op.DepartmentID, op.CategoryID, op.Priority, op.Mode, op.Status, op.Version, op.RequestedBy, op.ExpiresAt, input.TriggerEventID, op.AssignmentComment).Scan(&op.CreatedAt, &op.UpdatedAt)

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

// TryOperationLock пытается захватить транзакционную advisory-блокировку операции
// между репликами, удерживая соединение lockDB. При успехе вызывающий код обязан
// вызвать возвращённую идемпотентную функцию освобождения; занятая операция даёт acquired=false.
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
			// Откат выполняется даже после отмены запроса, чтобы PgBouncer освободил закреплённое соединение.
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

// Get читает актуальную операцию из primary для принятия решений о переходах состояния.
// Отсутствие возвращает как ErrNotFound.
func (r *Repository) Get(ctx context.Context, id uuid.UUID) (*models.Operation, error) {
	op, err := scan(r.writeDB.QueryRow(ctx, baseSelect+` WHERE id=$1`, id))

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrNotFound
	}

	return op, err
}

// GetByTriggerEvent читает операцию по ID запускающего события из пула записи,
// чтобы повтор события видел актуальную запись. Отсутствие даёт ErrNotFound.
func (r *Repository) GetByTriggerEvent(ctx context.Context, eventID uuid.UUID) (*models.Operation, error) {
	op, err := scan(r.writeDB.QueryRow(ctx, baseSelect+` WHERE trigger_event_id=$1`, eventID))

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrNotFound
	}

	return op, err
}

// SetReserved переводит PENDING в RESERVED с заданной бригадой и событием outbox.
// Несовпадение версии expected, статуса или отсутствие записи даёт ErrConflict.
func (r *Repository) SetReserved(ctx context.Context, id, brigadeID uuid.UUID, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status='PENDING'", `brigade_id=$3,status='RESERVED',version=version+1,updated_at=now()`, "dispatch.reserved", nil, brigadeID)
}

// SetAssigned переводит RESERVED в ASSIGNED, сохраняет маршрут и событие outbox.
// Требует версию expected; нарушение условия перехода даёт ErrConflict.
func (r *Repository) SetAssigned(ctx context.Context, id, routeID uuid.UUID, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status='RESERVED'", `route_id=$3,status='ASSIGNED',version=version+1,updated_at=now()`, "dispatch.assigned", nil, routeID)
}

// SetExpired завершает просроченную операцию после успешного освобождения резерва.
// Отмена выполняется отдельным Cancel с постоянной записью компенсации.
func (r *Repository) SetExpired(ctx context.Context, id uuid.UUID, reason string, expected int32) (*models.Operation, error) {
	return r.transition(ctx, id, expected, "status IN ('PENDING','RESERVED')", `status='EXPIRED',failure_code='RESERVATION_EXPIRED',failure_stage='RESERVATION',failure_reason=$3,version=version+1,updated_at=now()`, "dispatch.expired", nil, nullable(reason))
}

// transition выполняет условное обновление операции и запись outbox в одной транзакции.
// guard и set задаются внутренним кодом, args начинаются с SQL-параметра $3;
// отсутствие строки с нужной версией и условием возвращает как ErrConflict.
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
		var dbErr *pgconn.PgError
		if errors.As(err, &dbErr) && dbErr.Code == "23505" {
			return nil, models.ErrConflict
		}
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

// List возвращает страницу операций по заявке, бригаде и статусу от новых к старым
// с отдельным общим счётчиком. Требует ненулевой in с подготовленными Limit и Offset.
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
	if in.DepartmentID != nil {
		add("department_id=$%d", *in.DepartmentID)
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
		return nil, 0, fmt.Errorf("count dispatch operations: %w", err)
	}

	args = append(args, in.Limit, in.Offset)
	rows, err := r.readDB.Query(ctx, baseSelect+" WHERE "+clause+fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)

	if err != nil {
		return nil, 0, fmt.Errorf("query dispatch operations: %w", err)
	}

	defer rows.Close()
	result := make([]*models.Operation, 0, in.Limit)
	for rows.Next() {
		item, scanErr := scan(rows)

		if scanErr != nil {
			return nil, 0, fmt.Errorf("scan dispatch operation: %w", scanErr)
		}

		result = append(result, item)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate dispatch operations: %w", err)
	}

	return result, total, nil
}

// Expire выбирает незавершённые компенсации и просроченные открытые операции.
// Не меняет их статусы; неположительный limit заменяет на 100.
func (r *Repository) Expire(ctx context.Context, limit int) ([]*models.Operation, error) {

	if limit <= 0 {
		limit = 100
	}

	rows, err := r.writeDB.Query(ctx, baseSelect+` WHERE release_pending OR (status IN ('PENDING','RESERVED','CONFIRMING') AND expires_at<=now()) ORDER BY updated_at,id LIMIT $1`, limit)

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

	return result, nil
}

// scan читает операцию в порядке baseSelect; при ошибке возвращает nil и исходную ошибку.
func scan(row scanner) (*models.Operation, error) {
	op := new(models.Operation)
	err := row.Scan(&op.ID, &op.TicketID, &op.DepartmentID, &op.CategoryID, &op.Priority, &op.BrigadeID, &op.RouteID, &op.Mode, &op.Status, &op.Version, &op.RequestedBy, &op.FailureCode, &op.FailureStage, &op.FailureReason, &op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt, &op.ReleasePending, &op.ReleaseActorID, &op.AssignmentComment)

	if err != nil {
		return nil, err
	}

	return op, nil
}

// nullable возвращает nil для пустой строки, чтобы сохранить SQL NULL, иначе — саму строку.
func nullable(value string) any {

	if value == "" {
		return nil
	}

	return value
}

const baseSelect = `SELECT id,ticket_id,department_id,category_id,COALESCE(priority,''),brigade_id,route_id,mode,status,version,requested_by,failure_code,failure_stage,failure_reason,expires_at,created_at,updated_at,release_pending,release_actor_id,assignment_comment FROM dispatch_operations`
const baseSelectUpdate = `UPDATE dispatch_operations SET `
const returning = ` RETURNING id,ticket_id,department_id,category_id,priority,brigade_id,route_id,mode,status,version,requested_by,failure_code,failure_stage,failure_reason,expires_at,created_at,updated_at,release_pending,release_actor_id,assignment_comment`
