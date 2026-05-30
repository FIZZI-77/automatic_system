package service

import (
	"context"
	"fmt"
	"time"

	"department/models"
	"department/pkg"
	"department/src/core/repository"

	"go.uber.org/zap"
)

type DepartmentServiceStruct struct {
	repo   *repository.Repository
	logger *zap.Logger
}

func NewDepartmentServiceStruct(repo *repository.Repository, logger *zap.Logger) *DepartmentServiceStruct {
	return &DepartmentServiceStruct{repo: repo, logger: logger}
}

func (s *DepartmentServiceStruct) CreateDepartment(ctx context.Context, in *models.CreateDepartmentInput) (*models.CreateDepartmentResult, error) {
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: CreateDepartment(): %w: %v", models.ErrValidation, err)
	}
	if !hasPrivilegedRole(in.ActorRoles) {
		return nil, fmt.Errorf("service: CreateDepartment(): %w", models.ErrPermissionDenied)
	}

	department, err := s.repo.CreateDepartment(ctx, in)
	if err != nil {
		logger.Error("CreateDepartment failed", zap.Duration("duration", time.Since(start)), zap.Error(err))
		return nil, fmt.Errorf("service: CreateDepartment(): %w", err)
	}

	return &models.CreateDepartmentResult{Department: department}, nil
}

func (s *DepartmentServiceStruct) GetDepartmentByID(ctx context.Context, in *models.GetDepartmentByIDInput) (*models.GetDepartmentByIDResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: GetDepartmentByID(): %w: %v", models.ErrValidation, err)
	}

	department, err := s.repo.GetDepartmentByID(ctx, in.ID)
	if err != nil {
		return nil, fmt.Errorf("service: GetDepartmentByID(): %w", err)
	}

	return &models.GetDepartmentByIDResult{Department: department}, nil
}

func (s *DepartmentServiceStruct) ListDepartments(ctx context.Context, in *models.ListDepartmentsInput) (*models.ListDepartmentsResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: ListDepartments(): %w: %v", models.ErrValidation, err)
	}

	departments, total, err := s.repo.ListDepartments(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ListDepartments(): %w", err)
	}

	return &models.ListDepartmentsResult{Departments: departments, Total: total}, nil
}

func (s *DepartmentServiceStruct) UpdateDepartment(ctx context.Context, in *models.UpdateDepartmentInput) (*models.UpdateDepartmentResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: UpdateDepartment(): %w: %v", models.ErrValidation, err)
	}
	if !hasPrivilegedRole(in.ActorRoles) {
		return nil, fmt.Errorf("service: UpdateDepartment(): %w", models.ErrPermissionDenied)
	}

	department, err := s.repo.UpdateDepartment(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: UpdateDepartment(): %w", err)
	}

	return &models.UpdateDepartmentResult{Department: department}, nil
}

func (s *DepartmentServiceStruct) DeleteDepartment(ctx context.Context, in *models.DeleteDepartmentInput) (*models.DeleteDepartmentResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: DeleteDepartment(): %w: %v", models.ErrValidation, err)
	}
	if !hasPrivilegedRole(in.ActorRoles) {
		return nil, fmt.Errorf("service: DeleteDepartment(): %w", models.ErrPermissionDenied)
	}

	department, err := s.repo.DeleteDepartment(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: DeleteDepartment(): %w", err)
	}

	return &models.DeleteDepartmentResult{Department: department}, nil
}

func hasPrivilegedRole(roles []string) bool {
	for _, role := range roles {
		if role == "admin" || role == "dispatcher" {
			return true
		}
	}
	return false
}
