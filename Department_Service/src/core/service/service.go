package service

import (
	"context"

	"department/models"
	"department/src/core/repository"

	"go.uber.org/zap"
)

type DepartmentService interface {
	CreateDepartment(ctx context.Context, in *models.CreateDepartmentInput) (*models.CreateDepartmentResult, error)
	GetDepartmentByID(ctx context.Context, in *models.GetDepartmentByIDInput) (*models.GetDepartmentByIDResult, error)
	ListDepartments(ctx context.Context, in *models.ListDepartmentsInput) (*models.ListDepartmentsResult, error)
	UpdateDepartment(ctx context.Context, in *models.UpdateDepartmentInput) (*models.UpdateDepartmentResult, error)
	DeleteDepartment(ctx context.Context, in *models.DeleteDepartmentInput) (*models.DeleteDepartmentResult, error)
}

type Service struct {
	DepartmentService
}

func NewService(repo *repository.Repository, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Service{
		DepartmentService: NewDepartmentServiceStruct(repo, logger),
	}
}
