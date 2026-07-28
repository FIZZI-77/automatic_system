package repository

import (
	"context"

	"department/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DepartmentRepository interface {
	CreateDepartment(ctx context.Context, in *models.CreateDepartmentInput) (*models.Department, error)
	GetDepartmentByID(ctx context.Context, id uuid.UUID) (*models.Department, error)
	ListDepartments(ctx context.Context, in *models.ListDepartmentsInput) ([]*models.Department, int64, error)
	UpdateDepartment(ctx context.Context, in *models.UpdateDepartmentInput) (*models.Department, error)
	DeleteDepartment(ctx context.Context, in *models.DeleteDepartmentInput) (*models.Department, error)
}

type Repository struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
	DepartmentRepository
}

func NewRepository(pools DBPools) *Repository {
	if pools.Read == nil {
		pools.Read = pools.Write
	}

	return &Repository{
		writePool:            pools.Write,
		readPool:             pools.Read,
		DepartmentRepository: NewDepartmentRepository(pools.Write, pools.Read),
	}
}
