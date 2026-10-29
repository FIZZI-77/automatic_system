package repository

import (
	"context"

	"department/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DepartmentRepository interface {
	// CreateDepartment сохраняет ведомство ACTIVE и событие создания; дубликат даёт ErrAlreadyExists.
	CreateDepartment(ctx context.Context, in *models.CreateDepartmentInput) (*models.Department, error)
	// GetDepartmentByID возвращает ведомство, включая архивное, либо ErrNotFound.
	GetDepartmentByID(ctx context.Context, id uuid.UUID) (*models.Department, error)
	// ListDepartments возвращает страницу ведомств по фильтрам и отдельный общий счётчик.
	ListDepartments(ctx context.Context, in *models.ListDepartmentsInput) ([]*models.Department, int64, error)
	// UpdateDepartment меняет заданные поля и записывает outbox; nil поля сохраняют прежние значения.
	UpdateDepartment(ctx context.Context, in *models.UpdateDepartmentInput) (*models.Department, error)
	// DeleteDepartment архивирует ведомство без удаления строки, сохраняя событие outbox.
	DeleteDepartment(ctx context.Context, in *models.DeleteDepartmentInput) (*models.Department, error)
}

type Repository struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
	DepartmentRepository
}

// NewRepository объединяет операции ведомств и идемпотентности.
// При nil pools.Read использует pools.Write для чтения.
func NewRepository(pools DBPools) *Repository {

	if pools.Read == nil {
		pools.Read = pools.Write
	}

	departmentRepo := NewDepartmentRepository(pools.Write, pools.Read)
	return &Repository{
		writePool:            pools.Write,
		readPool:             pools.Read,
		DepartmentRepository: departmentRepo,
	}
}
