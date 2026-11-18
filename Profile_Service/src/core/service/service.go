package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"profile/models"
	profilepkg "profile/pkg"
	"profile/src/core/repository"
)

type UserAccountChecker interface {
	// EnsureUserExists проверяет существование аккаунта и возвращает ошибку при отсутствии или сбое проверки.
	EnsureUserExists(ctx context.Context, userID uuid.UUID) error
}

type DepartmentChecker interface {
	// EnsureDepartmentActive проверяет существование и активность ведомства перед изменением рабочего профиля.
	EnsureDepartmentActive(ctx context.Context, departmentID uuid.UUID) error
}

type UserProfileService interface {
	// CreateUserProfile создаёт профиль для себя или администратора с проверкой данных и идемпотентностью.
	CreateUserProfile(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error)
	// GetUserProfileByID возвращает профиль по ID владельцу или администратору.
	GetUserProfileByID(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error)
	// GetUserProfileByUserID возвращает профиль по пользователю владельцу или администратору.
	GetUserProfileByUserID(ctx context.Context, in *models.GetUserProfileByUserIDInput) (*models.GetUserProfileByUserIDResult, error)
	// GetMyUserProfile возвращает профиль пользователя, заданного в ActorUserID.
	GetMyUserProfile(ctx context.Context, in *models.GetMyUserProfileInput) (*models.GetMyUserProfileResult, error)
	// ListUserProfiles возвращает страницу профилей администратору, нормализуя фильтр in.
	ListUserProfiles(ctx context.Context, in *models.ListUserProfilesInput) (*models.ListUserProfilesResult, error)
	// UpdateUserProfile обновляет заданные поля для владельца или администратора с идемпотентностью.
	UpdateUserProfile(ctx context.Context, in *models.UpdateUserProfileInput) (*models.UpdateUserProfileResult, error)
}

type WorkProfileService interface {
	// CreateWorkProfile создаёт рабочий профиль для администратора с проверкой пользователя и ведомства.
	CreateWorkProfile(ctx context.Context, in *models.CreateWorkProfileInput) (*models.CreateWorkProfileResult, error)
	// GetWorkProfileByID возвращает профиль владельцу, администратору или диспетчеру своего ведомства.
	GetWorkProfileByID(ctx context.Context, in *models.GetWorkProfileByIDInput) (*models.GetWorkProfileByIDResult, error)
	// GetWorkProfileByUserID возвращает профиль пользователя с проверкой доступа к рабочему профилю.
	GetWorkProfileByUserID(ctx context.Context, in *models.GetWorkProfileByUserIDInput) (*models.GetWorkProfileByUserIDResult, error)
	// ListWorkProfiles возвращает страницу администратору или диспетчеру своего ведомства, нормализуя in.
	ListWorkProfiles(ctx context.Context, in *models.ListWorkProfilesInput) (*models.ListWorkProfilesResult, error)
	// UpdateWorkProfile меняет должность и табельный номер для администратора с идемпотентностью.
	UpdateWorkProfile(ctx context.Context, in *models.UpdateWorkProfileInput) (*models.UpdateWorkProfileResult, error)
	// DeactivateWorkProfile деактивирует профиль для администратора с причиной и идемпотентностью.
	DeactivateWorkProfile(ctx context.Context, in *models.DeactivateWorkProfileInput) (*models.DeactivateWorkProfileResult, error)
	// ChangeWorkProfileDepartment переводит профиль в проверенное ведомство для администратора с идемпотентностью.
	ChangeWorkProfileDepartment(ctx context.Context, in *models.ChangeWorkProfileDepartmentInput) (*models.ChangeWorkProfileDepartmentResult, error)
	// SetWorkProfileStatus меняет статус с идемпотентностью; права и переход проверяются под блокировкой в хранилище.
	SetWorkProfileStatus(ctx context.Context, in *models.SetWorkProfileStatusInput) (*models.SetWorkProfileStatusResult, error)
	// GetWorkProfileStatusHistory проверяет доступ и возвращает страницу истории с общим счётчиком.
	GetWorkProfileStatusHistory(ctx context.Context, in *models.GetWorkProfileStatusHistoryInput) (*models.GetWorkProfileStatusHistoryResult, error)
}

type ProfileInternalService interface {
	// ResolveWorkingDepartment возвращает рабочее ведомство пользователя и признак допуска к работе.
	ResolveWorkingDepartment(ctx context.Context, in *models.ResolveWorkingDepartmentInput) (*models.ResolveWorkingDepartmentResult, error)
	// CheckProfileCanJoinBrigade возвращает решение о включении в бригаду с причиной отказа.
	CheckProfileCanJoinBrigade(ctx context.Context, in *models.CheckProfileCanJoinBrigadeInput) (*models.CheckProfileCanJoinBrigadeResult, error)
}

type CertificationService interface {
	// CreateCertificationType создаёт тип сертификата для администратора с проверкой данных и идемпотентностью.
	CreateCertificationType(ctx context.Context, in *models.CreateCertificationTypeInput) (*models.CreateCertificationTypeResult, error)
	// UpdateCertificationType обновляет заданные поля типа для администратора с идемпотентностью.
	UpdateCertificationType(ctx context.Context, in *models.UpdateCertificationTypeInput) (*models.UpdateCertificationTypeResult, error)
	// ListCertificationTypes проверяет доступ к каталогу и возвращает страницу, нормализуя пагинацию в in.
	ListCertificationTypes(ctx context.Context, in *models.ListCertificationTypesInput) (*models.ListCertificationTypesResult, error)
	// AddCertificationTypeSkill связывает тип сертификата с навыком для администратора с идемпотентностью.
	AddCertificationTypeSkill(ctx context.Context, in *models.AddCertificationTypeSkillInput) (*models.AddCertificationTypeSkillResult, error)
	// RemoveCertificationTypeSkill удаляет связь типа с навыком для администратора с идемпотентностью.
	RemoveCertificationTypeSkill(ctx context.Context, in *models.RemoveCertificationTypeSkillInput) error
	// ListCertificationTypeSkills проверяет право чтения каталога и возвращает навыки типа сертификата.
	ListCertificationTypeSkills(ctx context.Context, in *models.ListCertificationTypeSkillsInput) (*models.ListCertificationTypeSkillsResult, error)
	// UploadWorkProfileCertification проверяет доступ, тип, срок и статус профиля и сохраняет сертификат с идемпотентностью.
	UploadWorkProfileCertification(ctx context.Context, in *models.UploadWorkProfileCertificationInput) (*models.UploadWorkProfileCertificationResult, error)
	// VerifyWorkProfileCertification подтверждает сертификат для администратора или кадрового проверяющего с идемпотентностью.
	VerifyWorkProfileCertification(ctx context.Context, in *models.VerifyWorkProfileCertificationInput) (*models.VerifyWorkProfileCertificationResult, error)
	// RejectWorkProfileCertification отклоняет сертификат с причиной для администратора или кадрового проверяющего.
	RejectWorkProfileCertification(ctx context.Context, in *models.RejectWorkProfileCertificationInput) (*models.RejectWorkProfileCertificationResult, error)
	// RevokeWorkProfileCertification отзывает сертификат с причиной для администратора или кадрового проверяющего.
	RevokeWorkProfileCertification(ctx context.Context, in *models.RevokeWorkProfileCertificationInput) (*models.RevokeWorkProfileCertificationResult, error)
	// ExpireWorkProfileCertifications обрабатывает пакет истёкших сертификатов для администратора или внутреннего вызова.
	ExpireWorkProfileCertifications(ctx context.Context, in *models.ExpireWorkProfileCertificationsInput) (*models.ExpireWorkProfileCertificationsResult, error)
	// ListWorkProfileCertifications проверяет доступ и возвращает страницу сертификатов, нормализуя пагинацию в in.
	ListWorkProfileCertifications(ctx context.Context, in *models.ListWorkProfileCertificationsInput) (*models.ListWorkProfileCertificationsResult, error)
	// GrantManualWorkProfileSkill вручную назначает навык для администратора или кадрового проверяющего с идемпотентностью.
	GrantManualWorkProfileSkill(ctx context.Context, in *models.GrantManualWorkProfileSkillInput) (*models.GrantManualWorkProfileSkillResult, error)
	// RevokeWorkProfileSkillGrant отзывает назначение навыка для администратора или кадрового проверяющего с идемпотентностью.
	RevokeWorkProfileSkillGrant(ctx context.Context, in *models.RevokeWorkProfileSkillGrantInput) (*models.RevokeWorkProfileSkillGrantResult, error)
	// ListEffectiveWorkProfileSkills проверяет доступ и возвращает действующие назначения навыков профиля.
	ListEffectiveWorkProfileSkills(ctx context.Context, in *models.ListEffectiveWorkProfileSkillsInput) (*models.ListEffectiveWorkProfileSkillsResult, error)
	// BatchListEffectiveWorkProfileSkills возвращает карту действующих навыков для администратора или внутреннего вызова.
	BatchListEffectiveWorkProfileSkills(ctx context.Context, in *models.BatchListEffectiveWorkProfileSkillsInput) (*models.BatchListEffectiveWorkProfileSkillsResult, error)
	// CheckWorkProfileHasSkills проверяет доступ и возвращает решение с недостающими навыками.
	CheckWorkProfileHasSkills(ctx context.Context, in *models.CheckWorkProfileHasSkillsInput) (*models.CheckWorkProfileHasSkillsResult, error)
}

type Service struct {
	UserProfileService
	WorkProfileService
	ProfileInternalService
	CertificationService
}

type Dependencies struct {
	UserAccountChecker UserAccountChecker
	DepartmentChecker  DepartmentChecker
}

// NewService объединяет пользовательские и рабочие профили, внутренние проверки
// и квалификации. nil logger заменяет журналом без вывода.
func NewService(repo *repository.Repository, deps Dependencies, logger *zap.Logger) *Service {

	if logger == nil {
		logger = zap.NewNop()
	}

	return &Service{
		UserProfileService:     NewUserProfileServiceStruct(repo, deps.UserAccountChecker, logger),
		WorkProfileService:     NewWorkProfileServiceStruct(repo, deps.DepartmentChecker, logger),
		ProfileInternalService: NewProfileInternalServiceStruct(repo, logger),
		CertificationService:   NewCertificationServiceStruct(repo, logger),
	}
}

// validationError добавляет имя метода и оборачивает ErrValidation,
// включая исходную err только как текст.
func validationError(method string, err error) error {
	return fmt.Errorf("service: %s(): %w: %v", method, models.ErrValidation, err)
}

// hasRole проверяет наличие любой разрешённой роли без учёта регистра.
// Крайние пробелы в ролях не удаляет.
func hasRole(roles []string, allowed ...string) bool {
	for _, role := range roles {
		for _, allow := range allowed {

			if strings.EqualFold(role, allow) {
				return true
			}

		}
	}
	return false
}

// isAdmin проверяет роль admin без учёта регистра.
func isAdmin(roles []string) bool {
	return hasRole(roles, "admin")
}

// isDispatcher проверяет роль dispatcher без учёта регистра.
func isDispatcher(roles []string) bool {
	return hasRole(roles, "dispatcher")
}

// isHR проверяет наличие роли hr или qualification_verifier без учёта регистра.
func isHR(roles []string) bool {
	return hasRole(roles, "hr", "qualification_verifier")
}

// actorKey возвращает UUID инициатора как ключ идемпотентности либо system
// для nil или нулевого UUID.
func actorKey(actorUserID *uuid.UUID) string {

	if actorUserID == nil || *actorUserID == uuid.Nil {
		return "system"
	}

	return actorUserID.String()
}

// isSelf сообщает, задан ли ActorUserID и совпадает ли он с userID.
func isSelf(actorUserID *uuid.UUID, userID uuid.UUID) bool {
	return actorUserID != nil && *actorUserID == userID
}

// permissionDenied возвращает ErrPermissionDenied с именем сервисного метода.
func permissionDenied(method string) error {
	return fmt.Errorf("service: %s(): %w", method, models.ErrPermissionDenied)
}

// wrapServiceError добавляет имя сервисного метода в цепочку err; nil сохраняет.
func wrapServiceError(method string, err error) error {

	if err == nil {
		return nil
	}

	return fmt.Errorf("service: %s(): %w", method, err)
}

// startOperation добавляет request ID к журналу, пишет начало операции
// и возвращает журнал и время для измерения длительности. nil logger допускается.
func startOperation(ctx context.Context, logger *zap.Logger, method string, fields ...zap.Field) (*zap.Logger, time.Time) {

	if logger == nil {
		logger = zap.NewNop()
	}

	operationLogger := logger.With(profilepkg.RequestIDField(ctx))
	operationLogger.Info(method, fields...)

	return operationLogger, time.Now()
}

// logValidationFailed пишет предупреждение об ошибке проверки с длительностью в миллисекундах.
func logValidationFailed(logger *zap.Logger, method string, start time.Time, err error, fields ...zap.Field) {
	fields = append(fields,
		zap.Int64("duration_ms", time.Since(start).Milliseconds()),
		zap.Error(err),
	)
	logger.Warn(method+" validation failed", fields...)
}

// logPermissionDenied пишет предупреждение об отказе в доступе с длительностью операции.
func logPermissionDenied(logger *zap.Logger, method string, start time.Time, fields ...zap.Field) {
	fields = append(fields, zap.Int64("duration_ms", time.Since(start).Milliseconds()))
	logger.Warn(method+" permission denied", fields...)
}

// logOperationFailed пишет ошибку операции с её причиной и длительностью в миллисекундах.
func logOperationFailed(logger *zap.Logger, method string, start time.Time, err error, fields ...zap.Field) {
	fields = append(fields,
		zap.Int64("duration_ms", time.Since(start).Milliseconds()),
		zap.Error(err),
	)
	logger.Error(method+" failed", fields...)
}

// logOperationSuccess пишет успешное завершение операции с длительностью в миллисекундах.
func logOperationSuccess(logger *zap.Logger, method string, start time.Time, fields ...zap.Field) {
	fields = append(fields, zap.Int64("duration_ms", time.Since(start).Milliseconds()))
	logger.Info(method+" success", fields...)
}

// runCommand выполняет команду с идемпотентностью по методу и инициатору,
// добавляя имя метода к ошибке. Без ключа в контексте выполняет команду напрямую.
func runCommand[T any](
	ctx context.Context,
	repo *repository.Repository,
	method string,
	actorUserID *uuid.UUID,
	request any,
	command func(context.Context) (*T, uuid.UUID, error),
) (*T, error) {
	result, err := withIdempotency(ctx, repo, method, actorKey(actorUserID), request, command)

	if err != nil {
		return nil, wrapServiceError(method, err)
	}

	return result, nil
}
