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
	EnsureUserExists(ctx context.Context, userID uuid.UUID) error
}

type DepartmentChecker interface {
	EnsureDepartmentActive(ctx context.Context, departmentID uuid.UUID) error
}

type UserProfileService interface {
	CreateUserProfile(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error)
	GetUserProfileByID(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error)
	GetUserProfileByUserID(ctx context.Context, in *models.GetUserProfileByUserIDInput) (*models.GetUserProfileByUserIDResult, error)
	GetMyUserProfile(ctx context.Context, in *models.GetMyUserProfileInput) (*models.GetMyUserProfileResult, error)
	ListUserProfiles(ctx context.Context, in *models.ListUserProfilesInput) (*models.ListUserProfilesResult, error)
	UpdateUserProfile(ctx context.Context, in *models.UpdateUserProfileInput) (*models.UpdateUserProfileResult, error)
}

type WorkProfileService interface {
	CreateWorkProfile(ctx context.Context, in *models.CreateWorkProfileInput) (*models.CreateWorkProfileResult, error)
	GetWorkProfileByID(ctx context.Context, in *models.GetWorkProfileByIDInput) (*models.GetWorkProfileByIDResult, error)
	GetWorkProfileByUserID(ctx context.Context, in *models.GetWorkProfileByUserIDInput) (*models.GetWorkProfileByUserIDResult, error)
	ListWorkProfiles(ctx context.Context, in *models.ListWorkProfilesInput) (*models.ListWorkProfilesResult, error)
	UpdateWorkProfile(ctx context.Context, in *models.UpdateWorkProfileInput) (*models.UpdateWorkProfileResult, error)
	DeactivateWorkProfile(ctx context.Context, in *models.DeactivateWorkProfileInput) (*models.DeactivateWorkProfileResult, error)
	ChangeWorkProfileDepartment(ctx context.Context, in *models.ChangeWorkProfileDepartmentInput) (*models.ChangeWorkProfileDepartmentResult, error)
	SetWorkProfileStatus(ctx context.Context, in *models.SetWorkProfileStatusInput) (*models.SetWorkProfileStatusResult, error)
	GetWorkProfileStatusHistory(ctx context.Context, in *models.GetWorkProfileStatusHistoryInput) (*models.GetWorkProfileStatusHistoryResult, error)
}

type ProfileInternalService interface {
	ResolveWorkingDepartment(ctx context.Context, in *models.ResolveWorkingDepartmentInput) (*models.ResolveWorkingDepartmentResult, error)
	CheckProfileCanJoinBrigade(ctx context.Context, in *models.CheckProfileCanJoinBrigadeInput) (*models.CheckProfileCanJoinBrigadeResult, error)
}

type CertificationService interface {
	CreateCertificationType(ctx context.Context, in *models.CreateCertificationTypeInput) (*models.CreateCertificationTypeResult, error)
	UpdateCertificationType(ctx context.Context, in *models.UpdateCertificationTypeInput) (*models.UpdateCertificationTypeResult, error)
	ListCertificationTypes(ctx context.Context, in *models.ListCertificationTypesInput) (*models.ListCertificationTypesResult, error)
	AddCertificationTypeSkill(ctx context.Context, in *models.AddCertificationTypeSkillInput) (*models.AddCertificationTypeSkillResult, error)
	RemoveCertificationTypeSkill(ctx context.Context, in *models.RemoveCertificationTypeSkillInput) error
	ListCertificationTypeSkills(ctx context.Context, in *models.ListCertificationTypeSkillsInput) (*models.ListCertificationTypeSkillsResult, error)
	UploadWorkProfileCertification(ctx context.Context, in *models.UploadWorkProfileCertificationInput) (*models.UploadWorkProfileCertificationResult, error)
	VerifyWorkProfileCertification(ctx context.Context, in *models.VerifyWorkProfileCertificationInput) (*models.VerifyWorkProfileCertificationResult, error)
	RejectWorkProfileCertification(ctx context.Context, in *models.RejectWorkProfileCertificationInput) (*models.RejectWorkProfileCertificationResult, error)
	RevokeWorkProfileCertification(ctx context.Context, in *models.RevokeWorkProfileCertificationInput) (*models.RevokeWorkProfileCertificationResult, error)
	ExpireWorkProfileCertifications(ctx context.Context, in *models.ExpireWorkProfileCertificationsInput) (*models.ExpireWorkProfileCertificationsResult, error)
	ListWorkProfileCertifications(ctx context.Context, in *models.ListWorkProfileCertificationsInput) (*models.ListWorkProfileCertificationsResult, error)
	GrantManualWorkProfileSkill(ctx context.Context, in *models.GrantManualWorkProfileSkillInput) (*models.GrantManualWorkProfileSkillResult, error)
	RevokeWorkProfileSkillGrant(ctx context.Context, in *models.RevokeWorkProfileSkillGrantInput) (*models.RevokeWorkProfileSkillGrantResult, error)
	ListEffectiveWorkProfileSkills(ctx context.Context, in *models.ListEffectiveWorkProfileSkillsInput) (*models.ListEffectiveWorkProfileSkillsResult, error)
	BatchListEffectiveWorkProfileSkills(ctx context.Context, in *models.BatchListEffectiveWorkProfileSkillsInput) (*models.BatchListEffectiveWorkProfileSkillsResult, error)
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

func validationError(method string, err error) error {
	return fmt.Errorf("service: %s(): %w: %v", method, models.ErrValidation, err)
}

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

func isAdmin(roles []string) bool {
	return hasRole(roles, "admin")
}

func isDispatcher(roles []string) bool {
	return hasRole(roles, "dispatcher")
}

func isHR(roles []string) bool {
	return hasRole(roles, "hr", "qualification_verifier")
}

func actorKey(actorUserID *uuid.UUID) string {
	if actorUserID == nil || *actorUserID == uuid.Nil {
		return "system"
	}
	return actorUserID.String()
}

func isSelf(actorUserID *uuid.UUID, userID uuid.UUID) bool {
	return actorUserID != nil && *actorUserID == userID
}

func permissionDenied(method string) error {
	return fmt.Errorf("service: %s(): %w", method, models.ErrPermissionDenied)
}

func wrapServiceError(method string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("service: %s(): %w", method, err)
}

func startOperation(ctx context.Context, logger *zap.Logger, method string, fields ...zap.Field) (*zap.Logger, time.Time) {
	if logger == nil {
		logger = zap.NewNop()
	}

	operationLogger := logger.With(profilepkg.RequestIDField(ctx))
	operationLogger.Info(method, fields...)

	return operationLogger, time.Now()
}

func logValidationFailed(logger *zap.Logger, method string, start time.Time, err error, fields ...zap.Field) {
	fields = append(fields,
		zap.Int64("duration_ms", time.Since(start).Milliseconds()),
		zap.Error(err),
	)
	logger.Warn(method+" validation failed", fields...)
}

func logPermissionDenied(logger *zap.Logger, method string, start time.Time, fields ...zap.Field) {
	fields = append(fields, zap.Int64("duration_ms", time.Since(start).Milliseconds()))
	logger.Warn(method+" permission denied", fields...)
}

func logOperationFailed(logger *zap.Logger, method string, start time.Time, err error, fields ...zap.Field) {
	fields = append(fields,
		zap.Int64("duration_ms", time.Since(start).Milliseconds()),
		zap.Error(err),
	)
	logger.Error(method+" failed", fields...)
}

func logOperationSuccess(logger *zap.Logger, method string, start time.Time, fields ...zap.Field) {
	fields = append(fields, zap.Int64("duration_ms", time.Since(start).Milliseconds()))
	logger.Info(method+" success", fields...)
}

func runLoggedQuery[T any](
	ctx context.Context,
	logger *zap.Logger,
	method string,
	fields []zap.Field,
	query func() (*T, error),
	successFields func(*T) []zap.Field,
) (*T, error) {
	operationLogger, start := startOperation(ctx, logger, method, fields...)

	result, err := query()
	if err != nil {
		logOperationFailed(operationLogger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}

	logOperationSuccess(operationLogger, method, start, successFields(result)...)
	return result, nil
}

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

func runLoggedCommand[T any](
	ctx context.Context,
	logger *zap.Logger,
	repo *repository.Repository,
	method string,
	actorUserID *uuid.UUID,
	request any,
	fields []zap.Field,
	command func(context.Context) (*T, uuid.UUID, error),
	successFields func(*T) []zap.Field,
) (*T, error) {
	operationLogger, start := startOperation(ctx, logger, method, fields...)

	result, err := runCommand(ctx, repo, method, actorUserID, request, command)
	if err != nil {
		logOperationFailed(operationLogger, method, start, err, fields...)
		return nil, err
	}

	logOperationSuccess(operationLogger, method, start, successFields(result)...)
	return result, nil
}
