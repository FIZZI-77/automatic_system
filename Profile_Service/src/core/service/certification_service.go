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

// NewCertificationServiceStruct создаёт сервис сертификатов и навыков;
// nil logger заменяет журналом без вывода.
func NewCertificationServiceStruct(repo *repository.Repository, logger *zap.Logger) *CertificationServiceStruct {

	if logger == nil {
		logger = zap.NewNop()
	}

	return &CertificationServiceStruct{repo: repo, logger: logger}
}

// CreateCertificationType проверяет данные и создаёт тип сертификата для администратора
// с идемпотентностью. Требует ненулевой in.
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

// UpdateCertificationType проверяет изменения и обновляет тип сертификата
// для администратора с идемпотентностью. Требует ненулевой in.
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

// ListCertificationTypes проверяет право чтения каталога, нормализует пагинацию в in
// и возвращает страницу типов с общим счётчиком. Требует ненулевой in.
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

// AddCertificationTypeSkill проверяет данные и связывает тип сертификата с навыком
// для администратора с идемпотентностью. Требует ненулевой in.
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

// RemoveCertificationTypeSkill проверяет ID и удаляет связь типа сертификата
// с навыком для администратора с идемпотентностью. Требует ненулевой in.
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

// ListCertificationTypeSkills проверяет ID и право чтения каталога и возвращает
// навыки типа сертификата. Требует ненулевой in.
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

// UploadWorkProfileCertification проверяет данные, активность типа, требование файла,
// срок и право владельца, администратора или кадрового проверяющего. Сохраняет
// сертификат с идемпотентностью, отклоняя INACTIVE/SUSPENDED-профиль. Требует ненулевой in.
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

// VerifyWorkProfileCertification проверяет ID и инициатора и подтверждает сертификат
// через хранилище для администратора или кадрового проверяющего с идемпотентностью.
// Требует ненулевой in.
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

// RejectWorkProfileCertification проверяет ID и причину и отклоняет сертификат
// для администратора или кадрового проверяющего с идемпотентностью. Требует ненулевой in.
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

// RevokeWorkProfileCertification проверяет ID и причину и отзывает сертификат
// для администратора или кадрового проверяющего с идемпотентностью. Требует ненулевой in.
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

// ExpireWorkProfileCertifications нормализует in.Limit и обрабатывает истёкшие
// сертификаты для администратора или внутреннего вызова без пользователя и ролей.
// Требует ненулевой in; возвращает сертификаты и отозванные назначения навыков из хранилища.
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

// ListWorkProfileCertifications проверяет параметры и доступ к квалификациям профиля,
// нормализует пагинацию в in и возвращает страницу сертификатов. Требует ненулевой in.
func (s *CertificationServiceStruct) ListWorkProfileCertifications(ctx context.Context, in *models.ListWorkProfileCertificationsInput) (*models.ListWorkProfileCertificationsResult, error) {
	const method = "ListWorkProfileCertifications"
	fields := []zap.Field{
		zap.String("work_profile_id", in.WorkProfileID.String()),
		zap.Int32("limit", in.Limit),
		zap.Int32("offset", in.Offset),
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

	result, err := s.repo.ListWorkProfileCertifications(ctx, in)

	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}

	logOperationSuccess(logger, method, start, zap.Int("count", len(result.Certifications)), zap.Int64("total", result.Total))
	return result, nil
}

// GrantManualWorkProfileSkill проверяет параметры и вручную назначает навык
// для администратора или кадрового проверяющего с идемпотентностью. Требует ненулевой in.
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

// RevokeWorkProfileSkillGrant проверяет ID и причину и отзывает назначение навыка
// для администратора или кадрового проверяющего с идемпотентностью. Требует ненулевой in.
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

// ListEffectiveWorkProfileSkills проверяет ID и доступ к квалификациям профиля
// и возвращает действующие назначения навыков из хранилища. Требует ненулевой in.
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

// BatchListEffectiveWorkProfileSkills проверяет список профилей и возвращает карту
// действующих навыков для администратора или внутреннего вызова без пользователя и ролей.
// Требует ненулевой in.
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

// CheckWorkProfileHasSkills проверяет запрос и доступ к квалификациям профиля,
// затем возвращает решение и недостающие навыки из хранилища. Требует ненулевой in.
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

// ensureCertificationCanBeUploaded читает тип и профиль, проверяет условия загрузки,
// доступ инициатора и допустимость статуса профиля. Сохранение не выполняет.
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

// ensureCertificationTypeAcceptsUpload требует активный тип, заданный файл при
// RequiresFile и будущий ExpiresAt, если он указан. Обе модели должны быть ненулевыми.
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

// ensureCanUploadCertification разрешает загрузку администратору, кадровому
// проверяющему или владельцу профиля; иначе возвращает ErrPermissionDenied с именем метода.
func ensureCanUploadCertification(method string, actorUserID *uuid.UUID, roles []string, details *models.WorkProfileDetails) error {

	if isAdmin(roles) || isHR(roles) || isSelf(actorUserID, details.UserProfile.UserID) {
		return nil
	}

	return permissionDenied(method)
}

// ensureWorkProfileAcceptsCertification отклоняет INACTIVE и SUSPENDED
// с ErrWorkProfileInactive; для остальных статусов возвращает nil.
func ensureWorkProfileAcceptsCertification(method string, workProfile *models.WorkProfile) error {
	switch workProfile.Status {
	case models.WorkProfileStatusInactive, models.WorkProfileStatusSuspended:
		return wrapServiceError(method, models.ErrWorkProfileInactive)
	default:
		return nil
	}
}

// ensureCanReadWorkProfile допускает внутренний вызов, администратора, кадрового
// проверяющего, владельца или диспетчера своего ведомства. Для внутреннего вызова
// профиль не читает; остальные случаи требуют существующий профиль.
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

// requireCatalogReader допускает администратора, кадрового проверяющего, диспетчера
// или внутренний вызов; иначе возвращает ErrPermissionDenied с именем метода.
func requireCatalogReader(method string, actorUserID *uuid.UUID, roles []string) error {

	if isAdmin(roles) || isHR(roles) || isDispatcher(roles) || isInternalCall(actorUserID, roles) {
		return nil
	}

	return permissionDenied(method)
}

// requireAdmin требует роль admin; иначе возвращает ErrPermissionDenied с именем метода.
func requireAdmin(method string, roles []string) error {

	if isAdmin(roles) {
		return nil
	}

	return permissionDenied(method)
}

// requireAdminOrHR допускает admin, hr или qualification_verifier;
// остальные роли дают ErrPermissionDenied с именем метода.
func requireAdminOrHR(method string, roles []string) error {

	if isAdmin(roles) || isHR(roles) {
		return nil
	}

	return permissionDenied(method)
}

// actorDepartmentID читает рабочее ведомство инициатора без проверки CanOperate.
// nil или нулевой ID даёт ErrPermissionDenied; ошибки хранилища сохраняются.
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

// isInternalCall распознаёт внутренний вызов по отсутствующему или нулевому
// ActorUserID и пустому списку ролей.
func isInternalCall(actorUserID *uuid.UUID, roles []string) bool {
	return (actorUserID == nil || *actorUserID == uuid.Nil) && len(roles) == 0
}
