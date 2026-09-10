package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"profile/models"
	"profile/src/core/repository"
)

type CertificationServiceStruct struct {
	repo   *repository.Repository
	logger *zap.Logger
}

func NewCertificationServiceStruct(repo *repository.Repository, logger *zap.Logger) *CertificationServiceStruct {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &CertificationServiceStruct{repo: repo, logger: logger}
}

func (s *CertificationServiceStruct) CreateCertificationType(ctx context.Context, in *models.CreateCertificationTypeInput) (*models.CreateCertificationTypeResult, error) {
	const method = "CreateCertificationType"
	fields := []zap.Field{zap.String("code", in.Code), zap.String("name", in.Name)}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := requireAdmin(method, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, err
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func(ctx context.Context) (*models.CreateCertificationTypeResult, uuid.UUID, error) {
		result, err := s.repo.CreateCertificationType(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.CertificationType.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("certification_type_id", result.CertificationType.ID.String()))
	return result, nil
}

func (s *CertificationServiceStruct) UpdateCertificationType(ctx context.Context, in *models.UpdateCertificationTypeInput) (*models.UpdateCertificationTypeResult, error) {
	const method = "UpdateCertificationType"
	fields := []zap.Field{zap.String("certification_type_id", in.ID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := requireAdmin(method, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, err
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func(ctx context.Context) (*models.UpdateCertificationTypeResult, uuid.UUID, error) {
		result, err := s.repo.UpdateCertificationType(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.CertificationType.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("certification_type_id", result.CertificationType.ID.String()))
	return result, nil
}

func (s *CertificationServiceStruct) ListCertificationTypes(ctx context.Context, in *models.ListCertificationTypesInput) (*models.ListCertificationTypesResult, error) {
	const method = "ListCertificationTypes"
	fields := []zap.Field{zap.Int32("limit", in.Limit), zap.Int32("offset", in.Offset)}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := requireCatalogReader(method, in.ActorUserID, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, err
	}

	result, err := s.repo.ListCertificationTypes(ctx, in)
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	logOperationSuccess(logger, method, start, zap.Int("count", len(result.CertificationTypes)), zap.Int64("total", result.Total))
	return result, nil
}

func (s *CertificationServiceStruct) AddCertificationTypeSkill(ctx context.Context, in *models.AddCertificationTypeSkillInput) (*models.AddCertificationTypeSkillResult, error) {
	const method = "AddCertificationTypeSkill"
	fields := []zap.Field{
		zap.String("certification_type_id", in.CertificationTypeID.String()),
		zap.String("skill_id", in.SkillID.String()),
	}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := requireAdmin(method, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, err
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func(ctx context.Context) (*models.AddCertificationTypeSkillResult, uuid.UUID, error) {
		result, err := s.repo.AddCertificationTypeSkill(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.CertificationTypeSkill.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("certification_type_skill_id", result.CertificationTypeSkill.ID.String()))
	return result, nil
}

func (s *CertificationServiceStruct) RemoveCertificationTypeSkill(ctx context.Context, in *models.RemoveCertificationTypeSkillInput) error {
	const method = "RemoveCertificationTypeSkill"
	fields := []zap.Field{
		zap.String("certification_type_id", in.CertificationTypeID.String()),
		zap.String("skill_id", in.SkillID.String()),
	}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return validationError(method, err)
	}
	if err := requireAdmin(method, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return err
	}

	_, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func(ctx context.Context) (*struct{}, uuid.UUID, error) {
		if err := s.repo.RemoveCertificationTypeSkill(ctx, in); err != nil {
			return nil, uuid.Nil, err
		}
		return &struct{}{}, in.CertificationTypeID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return err
	}
	logOperationSuccess(logger, method, start, fields...)
	return err
}

func (s *CertificationServiceStruct) ListCertificationTypeSkills(ctx context.Context, in *models.ListCertificationTypeSkillsInput) (*models.ListCertificationTypeSkillsResult, error) {
	const method = "ListCertificationTypeSkills"
	fields := []zap.Field{zap.String("certification_type_id", in.CertificationTypeID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := requireCatalogReader(method, in.ActorUserID, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, err
	}

	result, err := s.repo.ListCertificationTypeSkills(ctx, in)
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	logOperationSuccess(logger, method, start, zap.Int("count", len(result.Skills)))
	return result, nil
}

func (s *CertificationServiceStruct) UploadWorkProfileCertification(ctx context.Context, in *models.UploadWorkProfileCertificationInput) (*models.UploadWorkProfileCertificationResult, error) {
	const method = "UploadWorkProfileCertification"
	fields := []zap.Field{
		zap.String("work_profile_id", in.WorkProfileID.String()),
		zap.String("certification_type_id", in.CertificationTypeID.String()),
	}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := s.ensureCertificationCanBeUploaded(ctx, method, in); err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func(ctx context.Context) (*models.UploadWorkProfileCertificationResult, uuid.UUID, error) {
		result, err := s.repo.UploadWorkProfileCertification(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.Certification.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("certification_id", result.Certification.ID.String()))
	return result, nil
}

func (s *CertificationServiceStruct) VerifyWorkProfileCertification(ctx context.Context, in *models.VerifyWorkProfileCertificationInput) (*models.VerifyWorkProfileCertificationResult, error) {
	const method = "VerifyWorkProfileCertification"
	fields := []zap.Field{zap.String("certification_id", in.ID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := requireAdminOrHR(method, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, err
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func(ctx context.Context) (*models.VerifyWorkProfileCertificationResult, uuid.UUID, error) {
		result, err := s.repo.VerifyWorkProfileCertification(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.Certification.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("certification_id", result.Certification.ID.String()), zap.Int("skill_grants_count", len(result.SkillGrants)))
	return result, nil
}

func (s *CertificationServiceStruct) RejectWorkProfileCertification(ctx context.Context, in *models.RejectWorkProfileCertificationInput) (*models.RejectWorkProfileCertificationResult, error) {
	const method = "RejectWorkProfileCertification"
	fields := []zap.Field{zap.String("certification_id", in.ID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := requireAdminOrHR(method, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, err
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func(ctx context.Context) (*models.RejectWorkProfileCertificationResult, uuid.UUID, error) {
		result, err := s.repo.RejectWorkProfileCertification(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.Certification.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("certification_id", result.Certification.ID.String()))
	return result, nil
}

func (s *CertificationServiceStruct) RevokeWorkProfileCertification(ctx context.Context, in *models.RevokeWorkProfileCertificationInput) (*models.RevokeWorkProfileCertificationResult, error) {
	const method = "RevokeWorkProfileCertification"
	fields := []zap.Field{zap.String("certification_id", in.ID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := requireAdminOrHR(method, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, err
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func(ctx context.Context) (*models.RevokeWorkProfileCertificationResult, uuid.UUID, error) {
		result, err := s.repo.RevokeWorkProfileCertification(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.Certification.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("certification_id", result.Certification.ID.String()), zap.Int("revoked_grants_count", len(result.RevokedGrants)))
	return result, nil
}

func (s *CertificationServiceStruct) ExpireWorkProfileCertifications(ctx context.Context, in *models.ExpireWorkProfileCertificationsInput) (*models.ExpireWorkProfileCertificationsResult, error) {
	const method = "ExpireWorkProfileCertifications"
	fields := []zap.Field{zap.Int32("limit", in.Limit)}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if !isAdmin(in.ActorRoles) && !isInternalCall(in.ActorUserID, in.ActorRoles) {
		logPermissionDenied(logger, method, start, fields...)
		return nil, permissionDenied(method)
	}

	result, err := s.repo.ExpireWorkProfileCertifications(ctx, in)
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	logOperationSuccess(logger, method, start,
		zap.Int("expired_certifications_count", len(result.ExpiredCertifications)),
		zap.Int("revoked_grants_count", len(result.RevokedGrants)),
	)
	return result, nil
}

func (s *CertificationServiceStruct) ListWorkProfileCertifications(ctx context.Context, in *models.ListWorkProfileCertificationsInput) (*models.ListWorkProfileCertificationsResult, error) {
	const method = "ListWorkProfileCertifications"
	fields := []zap.Field{zap.String("work_profile_id", in.WorkProfileID.String()), zap.Int32("limit", in.Limit), zap.Int32("offset", in.Offset)}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := s.ensureCanReadWorkProfile(ctx, in.WorkProfileID, in.ActorUserID, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, wrapServiceError(method, err)
	}

	result, err := s.repo.ListWorkProfileCertifications(ctx, in)
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	logOperationSuccess(logger, method, start, zap.Int("count", len(result.Certifications)), zap.Int64("total", result.Total))
	return result, nil
}

func (s *CertificationServiceStruct) GrantManualWorkProfileSkill(ctx context.Context, in *models.GrantManualWorkProfileSkillInput) (*models.GrantManualWorkProfileSkillResult, error) {
	const method = "GrantManualWorkProfileSkill"
	fields := []zap.Field{
		zap.String("work_profile_id", in.WorkProfileID.String()),
		zap.String("skill_id", in.SkillID.String()),
	}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := requireAdminOrHR(method, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, err
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func(ctx context.Context) (*models.GrantManualWorkProfileSkillResult, uuid.UUID, error) {
		result, err := s.repo.GrantManualWorkProfileSkill(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.SkillGrant.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("skill_grant_id", result.SkillGrant.ID.String()))
	return result, nil
}

func (s *CertificationServiceStruct) RevokeWorkProfileSkillGrant(ctx context.Context, in *models.RevokeWorkProfileSkillGrantInput) (*models.RevokeWorkProfileSkillGrantResult, error) {
	const method = "RevokeWorkProfileSkillGrant"
	fields := []zap.Field{zap.String("skill_grant_id", in.ID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := requireAdminOrHR(method, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, err
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func(ctx context.Context) (*models.RevokeWorkProfileSkillGrantResult, uuid.UUID, error) {
		result, err := s.repo.RevokeWorkProfileSkillGrant(ctx, in)
		if err != nil {
			return nil, uuid.Nil, err
		}
		return result, result.SkillGrant.ID, nil
	})
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}
	logOperationSuccess(logger, method, start, zap.String("skill_grant_id", result.SkillGrant.ID.String()))
	return result, nil
}

func (s *CertificationServiceStruct) ListEffectiveWorkProfileSkills(ctx context.Context, in *models.ListEffectiveWorkProfileSkillsInput) (*models.ListEffectiveWorkProfileSkillsResult, error) {
	const method = "ListEffectiveWorkProfileSkills"
	fields := []zap.Field{zap.String("work_profile_id", in.WorkProfileID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := s.ensureCanReadWorkProfile(ctx, in.WorkProfileID, in.ActorUserID, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, wrapServiceError(method, err)
	}

	result, err := s.repo.ListEffectiveWorkProfileSkills(ctx, in)
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	logOperationSuccess(logger, method, start, zap.Int("skill_grants_count", len(result.SkillGrants)))
	return result, nil
}

func (s *CertificationServiceStruct) BatchListEffectiveWorkProfileSkills(ctx context.Context, in *models.BatchListEffectiveWorkProfileSkillsInput) (*models.BatchListEffectiveWorkProfileSkillsResult, error) {
	const method = "BatchListEffectiveWorkProfileSkills"
	fields := []zap.Field{zap.Int("work_profile_ids_count", len(in.WorkProfileIDs))}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if !isAdmin(in.ActorRoles) && !isInternalCall(in.ActorUserID, in.ActorRoles) {
		logPermissionDenied(logger, method, start, fields...)
		return nil, permissionDenied(method)
	}

	result, err := s.repo.BatchListEffectiveWorkProfileSkills(ctx, in)
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	logOperationSuccess(logger, method, start, zap.Int("work_profiles_count", len(result.SkillGrantsByWorkProfileID)))
	return result, nil
}

func (s *CertificationServiceStruct) CheckWorkProfileHasSkills(ctx context.Context, in *models.CheckWorkProfileHasSkillsInput) (*models.CheckWorkProfileHasSkillsResult, error) {
	const method = "CheckWorkProfileHasSkills"
	fields := []zap.Field{
		zap.String("work_profile_id", in.WorkProfileID.String()),
		zap.Int("required_skill_ids_count", len(in.RequiredSkillIDs)),
	}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}
	if err := s.ensureCanReadWorkProfile(ctx, in.WorkProfileID, in.ActorUserID, in.ActorRoles); err != nil {
		logPermissionDenied(logger, method, start, fields...)
		return nil, wrapServiceError(method, err)
	}

	result, err := s.repo.CheckWorkProfileHasSkills(ctx, in)
	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}
	logOperationSuccess(logger, method, start, zap.Bool("allowed", result.Allowed), zap.Int("missing_skill_ids_count", len(result.MissingSkillIDs)))
	return result, nil
}

func (s *CertificationServiceStruct) ensureCertificationCanBeUploaded(ctx context.Context, method string, in *models.UploadWorkProfileCertificationInput) error {
	certificationType, err := s.repo.GetCertificationTypeByID(ctx, in.CertificationTypeID)
	if err != nil {
		return wrapServiceError(method, err)
	}
	if err := ensureCertificationTypeAcceptsUpload(certificationType, in); err != nil {
		return validationError(method, err)
	}

	details, err := s.repo.GetWorkProfileByID(ctx, &models.GetWorkProfileByIDInput{ID: in.WorkProfileID})
	if err != nil {
		return wrapServiceError(method, err)
	}
	if err := ensureCanUploadCertification(method, in.ActorUserID, in.ActorRoles, details.Details); err != nil {
		return err
	}
	return ensureWorkProfileAcceptsCertification(method, details.Details.WorkProfile)
}

func ensureCertificationTypeAcceptsUpload(certificationType *models.CertificationType, in *models.UploadWorkProfileCertificationInput) error {
	if !certificationType.Active {
		return fmt.Errorf("certification type %s is inactive", certificationType.Code)
	}
	if certificationType.RequiresFile && in.CertificateFileID == nil {
		return fmt.Errorf("certificate_file_id is required for certification type %s", certificationType.Code)
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("expires_at must be in the future")
	}
	return nil
}

func ensureCanUploadCertification(method string, actorUserID *uuid.UUID, roles []string, details *models.WorkProfileDetails) error {
	if isAdmin(roles) || isHR(roles) || isSelf(actorUserID, details.UserProfile.UserID) {
		return nil
	}
	return permissionDenied(method)
}

func ensureWorkProfileAcceptsCertification(method string, workProfile *models.WorkProfile) error {
	switch workProfile.Status {
	case models.WorkProfileStatusInactive, models.WorkProfileStatusSuspended:
		return wrapServiceError(method, models.ErrWorkProfileInactive)
	default:
		return nil
	}
}

func (s *CertificationServiceStruct) ensureCanReadWorkProfile(ctx context.Context, workProfileID uuid.UUID, actorUserID *uuid.UUID, roles []string) error {
	if isInternalCall(actorUserID, roles) {
		return nil
	}

	details, err := s.repo.GetWorkProfileByID(ctx, &models.GetWorkProfileByIDInput{ID: workProfileID})
	if err != nil {
		return err
	}
	if isAdmin(roles) || isHR(roles) || isSelf(actorUserID, details.Details.UserProfile.UserID) {
		return nil
	}
	if !isDispatcher(roles) {
		return models.ErrPermissionDenied
	}

	departmentID, err := s.actorDepartmentID(ctx, actorUserID)
	if err != nil {
		return err
	}
	if departmentID != details.Details.WorkProfile.DepartmentID {
		return models.ErrPermissionDenied
	}
	return nil
}

func requireCatalogReader(method string, actorUserID *uuid.UUID, roles []string) error {
	if isAdmin(roles) || isHR(roles) || isDispatcher(roles) || isInternalCall(actorUserID, roles) {
		return nil
	}
	return permissionDenied(method)
}

func requireAdmin(method string, roles []string) error {
	if isAdmin(roles) {
		return nil
	}
	return permissionDenied(method)
}

func requireAdminOrHR(method string, roles []string) error {
	if isAdmin(roles) || isHR(roles) {
		return nil
	}
	return permissionDenied(method)
}

func (s *CertificationServiceStruct) actorDepartmentID(ctx context.Context, actorUserID *uuid.UUID) (uuid.UUID, error) {
	if actorUserID == nil || *actorUserID == uuid.Nil {
		return uuid.Nil, models.ErrPermissionDenied
	}

	result, err := s.repo.ResolveWorkingDepartment(ctx, &models.ResolveWorkingDepartmentInput{UserID: *actorUserID})
	if err != nil {
		return uuid.Nil, err
	}
	return result.DepartmentID, nil
}

func isInternalCall(actorUserID *uuid.UUID, roles []string) bool {
	return (actorUserID == nil || *actorUserID == uuid.Nil) && len(roles) == 0
}
