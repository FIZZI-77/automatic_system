package repository

import (
	"context"
	"errors"
	"fmt"

	"department/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type scanner interface {
	Scan(dest ...any) error
}

type DepartmentRepoStruct struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
}

func NewDepartmentRepository(writePool *pgxpool.Pool, readPool *pgxpool.Pool) *DepartmentRepoStruct {
	if readPool == nil {
		readPool = writePool
	}

	return &DepartmentRepoStruct{writePool: writePool, readPool: readPool}
}

func (r *DepartmentRepoStruct) CreateDepartment(ctx context.Context, in *models.CreateDepartmentInput) (*models.Department, error) {
	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: CreateDepartment(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	department, err := r.createDepartment(ctx, tx, in)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: CreateDepartment(): commit: %w", err)
	}

	return department, nil
}

func (r *DepartmentRepoStruct) createDepartment(ctx context.Context, q Querier, in *models.CreateDepartmentInput) (*models.Department, error) {
	const query = `
		INSERT INTO departments (
			id,
			name,
			description,
			status,
			created_at,
			updated_at
		)
		VALUES ($1, $2, $3, $4, now(), now())
		RETURNING id, name, description, status, created_at, updated_at
	`

	row := q.QueryRow(
		ctx,
		query,
		uuid.New(),
		in.Name,
		in.Description,
		models.DepartmentStatusActive,
	)

	department, err := scanDepartment(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("repository: CreateDepartment(): %w", models.ErrAlreadyExists)
		}
		return nil, fmt.Errorf("repository: CreateDepartment(): %w", err)
	}

	if err = insertOutboxEvent(ctx, q, "department", department.ID, "department.created", department); err != nil {
		return nil, fmt.Errorf("repository: CreateDepartment(): insert outbox event: %w", err)
	}

	return department, nil
}

func (r *DepartmentRepoStruct) GetDepartmentByID(ctx context.Context, id uuid.UUID) (*models.Department, error) {
	const query = `
		SELECT id, name, description, status, created_at, updated_at
		FROM departments
		WHERE id = $1
	`

	department, err := scanDepartment(r.readPool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("repository: GetDepartmentByID(): %w", err)
	}

	return department, nil
}

func (r *DepartmentRepoStruct) ListDepartments(ctx context.Context, in *models.ListDepartmentsInput) ([]*models.Department, int64, error) {
	whereSQL := "WHERE 1=1"
	args := make([]any, 0)

	if in.Status != nil {
		args = append(args, *in.Status)
		whereSQL += fmt.Sprintf(" AND status = $%d", len(args))
	}
	if in.CreatedFrom != nil {
		args = append(args, *in.CreatedFrom)
		whereSQL += fmt.Sprintf(" AND created_at >= $%d", len(args))
	}
	if in.CreatedTo != nil {
		args = append(args, *in.CreatedTo)
		whereSQL += fmt.Sprintf(" AND created_at <= $%d", len(args))
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM departments %s", whereSQL)

	var total int64
	if err := r.readPool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("repository: ListDepartments(): count: %w", err)
	}

	sortColumn := departmentSortColumn(in.SortBy)
	sortOrder := "DESC"
	if in.SortOrder == models.SortOrderAsc {
		sortOrder = "ASC"
	}

	args = append(args, in.Limit, in.Offset)
	limitArg := len(args) - 1
	offsetArg := len(args)

	listQuery := fmt.Sprintf(`
		SELECT id, name, description, status, created_at, updated_at
		FROM departments
		%s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d
	`, whereSQL, sortColumn, sortOrder, limitArg, offsetArg)

	rows, err := r.readPool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("repository: ListDepartments(): query: %w", err)
	}
	defer rows.Close()

	departments := make([]*models.Department, 0)
	for rows.Next() {
		department, err := scanDepartment(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("repository: ListDepartments(): scan: %w", err)
		}
		departments = append(departments, department)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("repository: ListDepartments(): rows: %w", err)
	}

	return departments, total, nil
}

func (r *DepartmentRepoStruct) UpdateDepartment(ctx context.Context, in *models.UpdateDepartmentInput) (*models.Department, error) {
	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: UpdateDepartment(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	department, err := r.updateDepartment(ctx, tx, in)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: UpdateDepartment(): commit: %w", err)
	}

	return department, nil
}

func (r *DepartmentRepoStruct) updateDepartment(ctx context.Context, q Querier, in *models.UpdateDepartmentInput) (*models.Department, error) {
	const query = `
		UPDATE departments
		SET
			name = COALESCE($1, name),
			description = COALESCE($2, description),
			status = COALESCE($3, status),
			updated_at = now()
		WHERE id = $4
		RETURNING id, name, description, status, created_at, updated_at
	`

	department, err := scanDepartment(q.QueryRow(ctx, query, in.Name, in.Description, in.Status, in.ID))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("repository: UpdateDepartment(): %w", models.ErrAlreadyExists)
		}
		return nil, fmt.Errorf("repository: UpdateDepartment(): %w", err)
	}

	if err = insertOutboxEvent(ctx, q, "department", department.ID, "department.updated", department); err != nil {
		return nil, fmt.Errorf("repository: UpdateDepartment(): insert outbox event: %w", err)
	}

	return department, nil
}

func (r *DepartmentRepoStruct) DeleteDepartment(ctx context.Context, in *models.DeleteDepartmentInput) (*models.Department, error) {
	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: DeleteDepartment(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	department, err := r.deleteDepartment(ctx, tx, in)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: DeleteDepartment(): commit: %w", err)
	}

	return department, nil
}

func (r *DepartmentRepoStruct) deleteDepartment(ctx context.Context, q Querier, in *models.DeleteDepartmentInput) (*models.Department, error) {
	const query = `
		UPDATE departments
		SET
			status = $1,
			updated_at = now()
		WHERE id = $2
		RETURNING id, name, description, status, created_at, updated_at
	`

	department, err := scanDepartment(q.QueryRow(ctx, query, models.DepartmentStatusArchived, in.ID))
	if err != nil {
		return nil, fmt.Errorf("repository: DeleteDepartment(): %w", err)
	}

	if err = insertOutboxEvent(ctx, q, "department", department.ID, "department.archived", department); err != nil {
		return nil, fmt.Errorf("repository: DeleteDepartment(): insert outbox event: %w", err)
	}

	return department, nil
}

func scanDepartment(s scanner) (*models.Department, error) {
	var department models.Department

	err := s.Scan(
		&department.ID,
		&department.Name,
		&department.Description,
		&department.Status,
		&department.CreatedAt,
		&department.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNotFound
		}
		return nil, err
	}

	return &department, nil
}

func departmentSortColumn(sortBy models.DepartmentSortBy) string {
	switch sortBy {
	case models.DepartmentSortByUpdatedAt:
		return "updated_at"
	case models.DepartmentSortByName:
		return "name"
	case models.DepartmentSortByStatus:
		return "status"
	default:
		return "created_at"
	}
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return true
	}

	return false
}
