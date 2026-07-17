package service

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"profile/models"
	"profile/src/core/repository"
)

type WorkProfileServiceStruct struct {
	repo              *repository.Repository
	departmentChecker DepartmentChecker
	logger            *zap.Logger
}

func NewWorkProfileServiceStruct(repo *repository.Repository, departmentChecker DepartmentChecker, logger *zap.Logger) *WorkProfileServiceStruct {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &WorkProfileServiceStruct{repo: repo, departmentChecker: departmentChecker, logger: logger}
}

func (s *WorkProfileServiceStruct) CreateWorkProfile(ctx context.Context, in *models.CreateWorkProfileInput) (*models.CreateWorkProfileResult, error) {
	const method = "CreateWorkProfile"
	fields := []zap.Field{
		zap.String("user_profile_id", in.UserProfileID.String()),
		zap.String("department_id", in.DepartmentID.String()),
	}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if !isAdmin(in.ActorRoles) {
		logPermissionDenied(logger, method, start, fields...)
		return nil, permissionDenied(method)
	}
	if _, err := s.repo.GetUserProfileByID(ctx, &models.GetUserProfileByIDInput{ID: in.UserProfileID}); err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	if err := s.ensureDepartmentActive(ctx, in.DepartmentID, method); err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func() (*models.CreateWorkProfileResult, uuid.UUID, error) {
		result, err := s.repo.CreateWorkProfile(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.Details.WorkProfile.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("work_profile_id", result.Details.WorkProfile.ID.String()))
	return result, nil
}

func (s *WorkProfileServiceStruct) GetWorkProfileByID(ctx context.Context, in *models.GetWorkProfileByIDInput) (*models.GetWorkProfileByIDResult, error) {
	const method = "GetWorkProfileByID"
	fields := []zap.Field{zap.String("work_profile_id", in.ID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}

	result, err := s.repo.GetWorkProfileByID(ctx, in)
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	if err = s.ensureCanReadWorkProfile(ctx, in.ActorUserID, in.ActorRoles, result.Details); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, wrapServiceError(method, err)
	}
	logOperationSuccess(logger, method, start, zap.String("work_profile_id", result.Details.WorkProfile.ID.String()))
	return result, nil
}

func (s *WorkProfileServiceStruct) GetWorkProfileByUserID(ctx context.Context, in *models.GetWorkProfileByUserIDInput) (*models.GetWorkProfileByUserIDResult, error) {
	const method = "GetWorkProfileByUserID"
	fields := []zap.Field{zap.String("user_id", in.UserID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}

	result, err := s.repo.GetWorkProfileByUserID(ctx, in)
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	if err = s.ensureCanReadWorkProfile(ctx, in.ActorUserID, in.ActorRoles, result.Details); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, wrapServiceError(method, err)
	}
	logOperationSuccess(logger, method, start, zap.String("work_profile_id", result.Details.WorkProfile.ID.String()))
	return result, nil
}

func (s *WorkProfileServiceStruct) ListWorkProfiles(ctx context.Context, in *models.ListWorkProfilesInput) (*models.ListWorkProfilesResult, error) {
	const method = "ListWorkProfiles"
	fields := []zap.Field{zap.Int32("limit", in.Limit), zap.Int32("offset", in.Offset)}
	if in.DepartmentID != nil {
		fields = append(fields, zap.String("department_id", in.DepartmentID.String()))
	}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}

	if !isAdmin(in.ActorRoles) {
		if !isDispatcher(in.ActorRoles) {
			logPermissionDenied(logger, method, start, fields...)
			return nil, permissionDenied(method)
		}
		departmentID, err := s.actorDepartmentID(ctx, in.ActorUserID)
		if err != nil {
			logOperationFailed(logger, method, start, err, fields...)
			return nil, wrapServiceError(method, err)
		}
		if in.DepartmentID != nil && *in.DepartmentID != departmentID {
			logPermissionDenied(logger, method, start, fields...)
			return nil, permissionDenied(method)
		}
		in.DepartmentID = &departmentID
	}

	result, err := s.repo.ListWorkProfiles(ctx, in)
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	logOperationSuccess(logger, method, start, zap.Int("count", len(result.WorkProfiles)), zap.Int64("total", result.Total))
	return result, nil
}

func (s *WorkProfileServiceStruct) UpdateWorkProfile(ctx context.Context, in *models.UpdateWorkProfileInput) (*models.UpdateWorkProfileResult, error) {
	const method = "UpdateWorkProfile"
	fields := []zap.Field{zap.String("work_profile_id", in.ID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if !isAdmin(in.ActorRoles) {
		logPermissionDenied(logger, method, start, fields...)
		return nil, permissionDenied(method)
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func() (*models.UpdateWorkProfileResult, uuid.UUID, error) {
		result, err := s.repo.UpdateWorkProfile(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.Details.WorkProfile.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("work_profile_id", result.Details.WorkProfile.ID.String()))
	return result, nil
}

func (s *WorkProfileServiceStruct) DeactivateWorkProfile(ctx context.Context, in *models.DeactivateWorkProfileInput) (*models.DeactivateWorkProfileResult, error) {
	const method = "DeactivateWorkProfile"
	fields := []zap.Field{zap.String("work_profile_id", in.ID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if !isAdmin(in.ActorRoles) {
		logPermissionDenied(logger, method, start, fields...)
		return nil, permissionDenied(method)
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func() (*models.DeactivateWorkProfileResult, uuid.UUID, error) {
		result, err := s.repo.DeactivateWorkProfile(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.Details.WorkProfile.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("work_profile_id", result.Details.WorkProfile.ID.String()))
	return result, nil
}

func (s *WorkProfileServiceStruct) ChangeWorkProfileDepartment(ctx context.Context, in *models.ChangeWorkProfileDepartmentInput) (*models.ChangeWorkProfileDepartmentResult, error) {
	const method = "ChangeWorkProfileDepartment"
	fields := []zap.Field{
		zap.String("work_profile_id", in.ID.String()),
		zap.String("department_id", in.DepartmentID.String()),
	}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if !isAdmin(in.ActorRoles) {
		logPermissionDenied(logger, method, start, fields...)
		return nil, permissionDenied(method)
	}
	if err := s.ensureDepartmentActive(ctx, in.DepartmentID, method); err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func() (*models.ChangeWorkProfileDepartmentResult, uuid.UUID, error) {
		result, err := s.repo.ChangeWorkProfileDepartment(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.Details.WorkProfile.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("work_profile_id", result.Details.WorkProfile.ID.String()))
	return result, nil
}

func (s *WorkProfileServiceStruct) SetWorkProfileStatus(ctx context.Context, in *models.SetWorkProfileStatusInput) (*models.SetWorkProfileStatusResult, error) {
	const method = "SetWorkProfileStatus"
	fields := []zap.Field{zap.String("work_profile_id", in.ID.String()), zap.String("status", string(in.Status))}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}

	current, err := s.repo.GetWorkProfileByID(ctx, &models.GetWorkProfileByIDInput{ID: in.ID})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	if !isAdmin(in.ActorRoles) {
		if !isSelf(in.ActorUserID, current.Details.UserProfile.UserID) {
			logPermissionDenied(logger, method, start, fields...)
			return nil, permissionDenied(method)
		}
		if !isWorkerStatusTransitionAllowed(current.Details.WorkProfile.Status, in.Status) {
			logOperationFailed(logger, method, start, models.ErrInvalidStatus, fields...)
			return nil, wrapServiceError(method, models.ErrInvalidStatus)
		}
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func() (*models.SetWorkProfileStatusResult, uuid.UUID, error) {
		result, err := s.repo.SetWorkProfileStatus(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.Details.WorkProfile.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("work_profile_id", result.Details.WorkProfile.ID.String()))
	return result, nil
}

func (s *WorkProfileServiceStruct) GetWorkProfileStatusHistory(ctx context.Context, in *models.GetWorkProfileStatusHistoryInput) (*models.GetWorkProfileStatusHistoryResult, error) {
	const method = "GetWorkProfileStatusHistory"
	fields := []zap.Field{zap.String("work_profile_id", in.WorkProfileID.String()), zap.Int32("limit", in.Limit), zap.Int32("offset", in.Offset)}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}

	details, err := s.repo.GetWorkProfileByID(ctx, &models.GetWorkProfileByIDInput{ID: in.WorkProfileID})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	if err = s.ensureCanReadWorkProfile(ctx, in.ActorUserID, in.ActorRoles, details.Details); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, wrapServiceError(method, err)
	}

	result, err := s.repo.GetWorkProfileStatusHistory(ctx, in)
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	logOperationSuccess(logger, method, start, zap.Int("count", len(result.History)), zap.Int64("total", result.Total))
	return result, nil
}

func (s *WorkProfileServiceStruct) ensureCanReadWorkProfile(ctx context.Context, actorUserID *uuid.UUID, roles []string, details *models.WorkProfileDetails) error {
	if isAdmin(roles) || isSelf(actorUserID, details.UserProfile.UserID) {
		return nil
	}
	if !isDispatcher(roles) {
		return models.ErrPermissionDenied
	}
	departmentID, err := s.actorDepartmentID(ctx, actorUserID)
	if err != nil {
		return err
	}
	if departmentID != details.WorkProfile.DepartmentID {
		return models.ErrPermissionDenied
	}
	return nil
}

func (s *WorkProfileServiceStruct) actorDepartmentID(ctx context.Context, actorUserID *uuid.UUID) (uuid.UUID, error) {
	if actorUserID == nil || *actorUserID == uuid.Nil {
		return uuid.Nil, models.ErrPermissionDenied
	}
	result, err := s.repo.ResolveWorkingDepartment(ctx, &models.ResolveWorkingDepartmentInput{UserID: *actorUserID})
	if err != nil {
		return uuid.Nil, err
	}
	return result.DepartmentID, nil
}

func (s *WorkProfileServiceStruct) ensureDepartmentActive(ctx context.Context, departmentID uuid.UUID, method string) error {
	if s.departmentChecker == nil {
		return nil
	}
	if err := s.departmentChecker.EnsureDepartmentActive(ctx, departmentID); err != nil {
		return wrapServiceError(method, err)
	}
	return nil
}

func isWorkerStatusTransitionAllowed(from models.WorkProfileStatus, to models.WorkProfileStatus) bool {
	if from == to {
		return true
	}
	return (from == models.WorkProfileStatusActive || from == models.WorkProfileStatusOffShift) && to == models.WorkProfileStatusOnShift ||
		from == models.WorkProfileStatusOnShift && to == models.WorkProfileStatusOffShift
}
