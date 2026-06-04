package repository

import (
	"context"
	"database/sql"
	"fmt"

	"department/models"

	"github.com/google/uuid"
)

type DepartmentRepository interface {
	CreateDepartment(ctx context.Context, in *models.CreateDepartmentInput) (*models.Department, error)
	GetDepartmentByID(ctx context.Context, id uuid.UUID) (*models.Department, error)
	ListDepartments(ctx context.Context, in *models.ListDepartmentsInput) ([]*models.Department, int64, error)
	UpdateDepartment(ctx context.Context, in *models.UpdateDepartmentInput) (*models.Department, error)
	DeleteDepartment(ctx context.Context, in *models.DeleteDepartmentInput) (*models.Department, error)
}

type Repository struct {
	db *sql.DB
	DepartmentRepository
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		db:                   db,
		DepartmentRepository: NewDepartmentRepository(db),
	}
}

func newRepositoryWithExecutor(exec DBTX) *Repository {
	return &Repository{
		DepartmentRepository: NewDepartmentRepository(exec),
	}
}

func (r *Repository) WithTx(ctx context.Context, fn func(txRepo *Repository) error) error {
	if r.db == nil {
		return fmt.Errorf("repository: WithTx(): root db is unavailable")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("repository: WithTx(): begin tx: %w", err)
	}
	defer tx.Rollback()

	if err = fn(newRepositoryWithExecutor(tx)); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("repository: WithTx(): commit: %w", err)
	}

	return nil
}
