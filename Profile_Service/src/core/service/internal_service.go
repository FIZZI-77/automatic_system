package service

import (
	"context"

	"go.uber.org/zap"
	"profile/models"
	"profile/src/core/repository"
)

type ProfileInternalServiceStruct struct {
	repo   *repository.Repository
	logger *zap.Logger
}

func NewProfileInternalServiceStruct(repo *repository.Repository, logger *zap.Logger) *ProfileInternalServiceStruct {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ProfileInternalServiceStruct{repo: repo, logger: logger}
}

func (s *ProfileInternalServiceStruct) ResolveWorkingDepartment(ctx context.Context, in *models.ResolveWorkingDepartmentInput) (*models.ResolveWorkingDepartmentResult, error) {
	const method = "ResolveWorkingDepartment"
	fields := []zap.Field{zap.String("user_id", in.UserID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	result, err := s.repo.ResolveWorkingDepartment(ctx, in)
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	logOperationSuccess(logger, method, start,
		zap.String("work_profile_id", result.WorkProfileID.String()),
		zap.String("department_id", result.DepartmentID.String()),
		zap.Bool("can_operate", result.CanOperate),
	)
	return result, nil
}

func (s *ProfileInternalServiceStruct) CheckProfileCanJoinBrigade(ctx context.Context, in *models.CheckProfileCanJoinBrigadeInput) (*models.CheckProfileCanJoinBrigadeResult, error) {
	const method = "CheckProfileCanJoinBrigade"
	fields := []zap.Field{zap.String("brigade_department_id", in.BrigadeDepartmentID.String())}
	if in.UserID != nil {
		fields = append(fields, zap.String("user_id", in.UserID.String()))
	}
	if in.WorkProfileID != nil {
		fields = append(fields, zap.String("work_profile_id", in.WorkProfileID.String()))
	}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	result, err := s.repo.CheckProfileCanJoinBrigade(ctx, in)
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	logOperationSuccess(logger, method, start,
		zap.String("work_profile_id", result.WorkProfileID.String()),
		zap.Bool("allowed", result.Allowed),
		zap.String("reason", string(result.Reason)),
	)
	return result, nil
}
