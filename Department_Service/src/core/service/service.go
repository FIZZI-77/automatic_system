package service

import (
	"context"

	"department/models"
	"department/src/core/repository"

	"go.uber.org/zap"
)

type DepartmentService interface {
	// CreateDepartment создаёт активное ведомство для admin или dispatcher с поддержкой идемпотентности.
	CreateDepartment(ctx context.Context, in *models.CreateDepartmentInput) (*models.CreateDepartmentResult, error)
	// GetDepartmentByID проверяет ID и возвращает ведомство, включая архивное.
	GetDepartmentByID(ctx context.Context, in *models.GetDepartmentByIDInput) (*models.GetDepartmentByIDResult, error)
	// ListDepartments проверяет фильтры, нормализует in и возвращает страницу с общим счётчиком.
	ListDepartments(ctx context.Context, in *models.ListDepartmentsInput) (*models.ListDepartmentsResult, error)
	// UpdateDepartment меняет заданные поля для admin или dispatcher с поддержкой идемпотентности.
	UpdateDepartment(ctx context.Context, in *models.UpdateDepartmentInput) (*models.UpdateDepartmentResult, error)
	// DeleteDepartment архивирует ведомство для admin или dispatcher с поддержкой идемпотентности.
	DeleteDepartment(ctx context.Context, in *models.DeleteDepartmentInput) (*models.DeleteDepartmentResult, error)
}

type Service struct {
	DepartmentService
}

// NewService объединяет операции сервиса ведомств; nil logger заменяет журналом без вывода.
func NewService(repo *repository.Repository, logger *zap.Logger) *Service {

	if logger == nil {
		logger = zap.NewNop()
	}

	return &Service{
		DepartmentService: NewDepartmentServiceStruct(repo, logger),
	}
}
