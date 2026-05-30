package repository

import (
	"context"
	"database/sql"

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
	DepartmentRepository
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		DepartmentRepository: NewDepartmentRepository(db),
	}
}
