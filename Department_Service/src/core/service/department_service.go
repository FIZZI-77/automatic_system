package service

import (
	"context"
	"fmt"
	"time"

	"department/models"
	"department/pkg"
	"department/src/core/repository"

	"github.com/google/uuid"
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

	logger.Info("CreateDepartment",
		zap.String("name", in.Name),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("CreateDepartment validation failed",
			zap.String("name", in.Name),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CreateDepartment(): %w: %v", models.ErrValidation, err)
	}
	if !hasPrivilegedRole(in.ActorRoles) {
		logger.Warn("CreateDepartment permission denied",
			zap.String("name", in.Name),
			zap.Int64("duration", time.Since(start).Milliseconds()),
		)
		return nil, fmt.Errorf("service: CreateDepartment(): %w", models.ErrPermissionDenied)
	}

	result, err := s.withIdempotency(ctx, "CreateDepartment", "", in, func(ctx context.Context) (any, uuid.UUID, error) {
		department, err := s.repo.CreateDepartment(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return &models.CreateDepartmentResult{Department: department}, department.ID, nil
	})
	if err != nil {
		logger.Error("CreateDepartment failed",
			zap.String("name", in.Name),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CreateDepartment(): %w", err)
	}
	createResult, err := cachedResult[models.CreateDepartmentResult](result)
	if err != nil {
		return nil, fmt.Errorf("service: CreateDepartment(): idempotency result: %w", err)
	}
	department := createResult.Department

	logger.Info("CreateDepartment success",
		zap.String("department_id", department.ID.String()),
		zap.String("name", department.Name),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return createResult, nil
}

func (s *DepartmentServiceStruct) GetDepartmentByID(ctx context.Context, in *models.GetDepartmentByIDInput) (*models.GetDepartmentByIDResult, error) {
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("GetDepartmentByID",
		zap.String("department_id", in.ID.String()),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("GetDepartmentByID validation failed",
			zap.String("department_id", in.ID.String()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetDepartmentByID(): %w: %v", models.ErrValidation, err)
	}

	department, err := s.repo.GetDepartmentByID(ctx, in.ID)
	if err != nil {
		logger.Error("GetDepartmentByID failed",
			zap.String("department_id", in.ID.String()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetDepartmentByID(): %w", err)
	}

	logger.Info("GetDepartmentByID success",
		zap.String("department_id", department.ID.String()),
		zap.String("name", department.Name),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return &models.GetDepartmentByIDResult{Department: department}, nil
}

func (s *DepartmentServiceStruct) ListDepartments(ctx context.Context, in *models.ListDepartmentsInput) (*models.ListDepartmentsResult, error) {
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("ListDepartments",
		zap.Int32("limit", in.Limit),
		zap.Int32("offset", in.Offset),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("ListDepartments validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListDepartments(): %w: %v", models.ErrValidation, err)
	}

	departments, total, err := s.repo.ListDepartments(ctx, in)
	if err != nil {
		logger.Error("ListDepartments failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListDepartments(): %w", err)
	}

	logger.Info("ListDepartments success",
		zap.Int("count", len(departments)),
		zap.Int64("total", total),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return &models.ListDepartmentsResult{Departments: departments, Total: total}, nil
}

func (s *DepartmentServiceStruct) UpdateDepartment(ctx context.Context, in *models.UpdateDepartmentInput) (*models.UpdateDepartmentResult, error) {
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("UpdateDepartment",
		zap.String("department_id", in.ID.String()),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("UpdateDepartment validation failed",
			zap.String("department_id", in.ID.String()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: UpdateDepartment(): %w: %v", models.ErrValidation, err)
	}
	if !hasPrivilegedRole(in.ActorRoles) {
		logger.Warn("UpdateDepartment permission denied",
			zap.String("department_id", in.ID.String()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
		)
		return nil, fmt.Errorf("service: UpdateDepartment(): %w", models.ErrPermissionDenied)
	}

	result, err := s.withIdempotency(ctx, "UpdateDepartment", "", in, func(ctx context.Context) (any, uuid.UUID, error) {
		department, err := s.repo.UpdateDepartment(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return &models.UpdateDepartmentResult{Department: department}, department.ID, nil
	})
	if err != nil {
		logger.Error("UpdateDepartment failed",
			zap.String("department_id", in.ID.String()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: UpdateDepartment(): %w", err)
	}
	updateResult, err := cachedResult[models.UpdateDepartmentResult](result)
	if err != nil {
		return nil, fmt.Errorf("service: UpdateDepartment(): idempotency result: %w", err)
	}
	department := updateResult.Department

	logger.Info("UpdateDepartment success",
		zap.String("department_id", department.ID.String()),
		zap.String("status", string(department.Status)),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return updateResult, nil
}

func (s *DepartmentServiceStruct) DeleteDepartment(ctx context.Context, in *models.DeleteDepartmentInput) (*models.DeleteDepartmentResult, error) {
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("DeleteDepartment",
		zap.String("department_id", in.ID.String()),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("DeleteDepartment validation failed",
			zap.String("department_id", in.ID.String()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: DeleteDepartment(): %w: %v", models.ErrValidation, err)
	}
	if !hasPrivilegedRole(in.ActorRoles) {
		logger.Warn("DeleteDepartment permission denied",
			zap.String("department_id", in.ID.String()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
		)
		return nil, fmt.Errorf("service: DeleteDepartment(): %w", models.ErrPermissionDenied)
	}

	result, err := s.withIdempotency(ctx, "DeleteDepartment", "", in, func(ctx context.Context) (any, uuid.UUID, error) {
		department, err := s.repo.DeleteDepartment(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return &models.DeleteDepartmentResult{Department: department}, department.ID, nil
	})
	if err != nil {
		logger.Error("DeleteDepartment failed",
			zap.String("department_id", in.ID.String()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: DeleteDepartment(): %w", err)
	}
	deleteResult, err := cachedResult[models.DeleteDepartmentResult](result)
	if err != nil {
		return nil, fmt.Errorf("service: DeleteDepartment(): idempotency result: %w", err)
	}
	department := deleteResult.Department

	logger.Info("DeleteDepartment success",
		zap.String("department_id", department.ID.String()),
		zap.String("status", string(department.Status)),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return deleteResult, nil
}

func hasPrivilegedRole(roles []string) bool {
	for _, role := range roles {
		if role == "admin" || role == "dispatcher" {
			return true
		}
	}
	return false
}
