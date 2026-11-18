package service

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"profile/models"
	"profile/src/core/repository"
)

type UserProfileServiceStruct struct {
	repo        *repository.Repository
	userChecker UserAccountChecker
	logger      *zap.Logger
}

// NewUserProfileServiceStruct создаёт сервис пользовательских профилей.
// nil userChecker отключает внешнюю проверку аккаунта, nil logger — вывод журнала.
func NewUserProfileServiceStruct(repo *repository.Repository, userChecker UserAccountChecker, logger *zap.Logger) *UserProfileServiceStruct {

	if logger == nil {
		logger = zap.NewNop()
	}

	return &UserProfileServiceStruct{repo: repo, userChecker: userChecker, logger: logger}
}

// CreateUserProfile проверяет данные и создаёт профиль для себя или администратора
// с поддержкой идемпотентности. При создании чужого профиля вызывает userChecker,
// если он задан. Требует ненулевой in; проверка может задать способ связи EMAIL в in.
func (s *UserProfileServiceStruct) CreateUserProfile(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error) {
	const method = "CreateUserProfile"
	fields := []zap.Field{zap.String("user_id", in.UserID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}

	if !isAdmin(in.ActorRoles) && !isSelf(in.ActorUserID, in.UserID) {
		logPermissionDenied(logger, method, start, fields...)
		return nil, permissionDenied(method)
	}

	if s.userChecker != nil && !isSelf(in.ActorUserID, in.UserID) {

		if err := s.userChecker.EnsureUserExists(ctx, in.UserID); err != nil {
			logOperationFailed(logger, method, start, err, fields...)
			return nil, wrapServiceError(method, err)
		}

	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func(ctx context.Context) (*models.CreateUserProfileResult, uuid.UUID, error) {
		result, err := s.repo.CreateUserProfile(ctx, in)

		if err != nil {
			return nil, uuid.Nil, err
		}

		return result, result.UserProfile.ID, nil
	})

	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}

	logOperationSuccess(logger, method, start, zap.String("user_profile_id", result.UserProfile.ID.String()))
	return result, nil
}

// GetUserProfileByID проверяет ID и возвращает профиль владельцу или администратору.
// Требует ненулевой in; чтение профиля предшествует проверке доступа.
func (s *UserProfileServiceStruct) GetUserProfileByID(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error) {
	const method = "GetUserProfileByID"
	fields := []zap.Field{zap.String("user_profile_id", in.ID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}

	result, err := s.repo.GetUserProfileByID(ctx, in)

	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}

	if !isAdmin(in.ActorRoles) && !isSelf(in.ActorUserID, result.UserProfile.UserID) {
		logPermissionDenied(logger, method, start, fields...)
		return nil, permissionDenied(method)
	}

	logOperationSuccess(logger, method, start, zap.String("user_profile_id", result.UserProfile.ID.String()))
	return result, nil
}

// GetUserProfileByUserID возвращает профиль по ID пользователя после проверки
// доступа владельца или администратора. Требует ненулевой in.
func (s *UserProfileServiceStruct) GetUserProfileByUserID(ctx context.Context, in *models.GetUserProfileByUserIDInput) (*models.GetUserProfileByUserIDResult, error) {
	const method = "GetUserProfileByUserID"
	fields := []zap.Field{zap.String("user_id", in.UserID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}

	if !isAdmin(in.ActorRoles) && !isSelf(in.ActorUserID, in.UserID) {
		logPermissionDenied(logger, method, start, fields...)
		return nil, permissionDenied(method)
	}

	result, err := s.repo.GetUserProfileByUserID(ctx, in)

	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}

	logOperationSuccess(logger, method, start, zap.String("user_profile_id", result.UserProfile.ID.String()))
	return result, nil
}

// GetMyUserProfile проверяет ActorUserID и возвращает профиль текущего пользователя.
// Требует ненулевой in; отсутствие профиля возвращает как ошибку хранилища с контекстом операции.
func (s *UserProfileServiceStruct) GetMyUserProfile(ctx context.Context, in *models.GetMyUserProfileInput) (*models.GetMyUserProfileResult, error) {
	const method = "GetMyUserProfile"
	fields := []zap.Field{}

	if in.ActorUserID != nil {
		fields = append(fields, zap.String("actor_user_id", in.ActorUserID.String()))
	}

	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}

	result, err := s.repo.GetUserProfileByUserID(ctx, &models.GetUserProfileByUserIDInput{UserID: *in.ActorUserID})

	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}

	logOperationSuccess(logger, method, start, zap.String("user_profile_id", result.UserProfile.ID.String()))
	return &models.GetMyUserProfileResult{UserProfile: result.UserProfile}, nil
}

// ListUserProfiles возвращает страницу профилей только администратору, предварительно
// проверяя и нормализуя сортировку и пагинацию в in. Требует ненулевой in.
func (s *UserProfileServiceStruct) ListUserProfiles(ctx context.Context, in *models.ListUserProfilesInput) (*models.ListUserProfilesResult, error) {
	const method = "ListUserProfiles"
	fields := []zap.Field{zap.Int32("limit", in.Limit), zap.Int32("offset", in.Offset)}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}

	if !isAdmin(in.ActorRoles) {
		logPermissionDenied(logger, method, start, fields...)
		return nil, permissionDenied(method)
	}

	result, err := s.repo.ListUserProfiles(ctx, in)

	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}

	logOperationSuccess(logger, method, start, zap.Int("count", len(result.UserProfiles)), zap.Int64("total", result.Total))
	return result, nil
}

// UpdateUserProfile проверяет изменения и доступ владельца или администратора,
// затем обновляет профиль с поддержкой идемпотентности. Требует ненулевой in.
func (s *UserProfileServiceStruct) UpdateUserProfile(ctx context.Context, in *models.UpdateUserProfileInput) (*models.UpdateUserProfileResult, error) {
	const method = "UpdateUserProfile"
	fields := []zap.Field{zap.String("user_profile_id", in.ID.String())}
	logger, start := startOperation(ctx, s.logger, method, fields...)

	if err := in.Validate(); err != nil {
		logValidationFailed(logger, method, start, err, fields...)
		return nil, validationError(method, err)
	}

	current, err := s.repo.GetUserProfileByID(ctx, &models.GetUserProfileByIDInput{ID: in.ID})

	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, wrapServiceError(method, err)
	}

	if !isAdmin(in.ActorRoles) && !isSelf(in.ActorUserID, current.UserProfile.UserID) {
		logPermissionDenied(logger, method, start, fields...)
		return nil, permissionDenied(method)
	}

	result, err := runCommand(ctx, s.repo, method, in.ActorUserID, in, func(ctx context.Context) (*models.UpdateUserProfileResult, uuid.UUID, error) {
		result, err := s.repo.UpdateUserProfile(ctx, in)

		if err != nil {
			return nil, uuid.Nil, err
		}

		return result, result.UserProfile.ID, nil
	})

	if err != nil {
		logOperationFailed(logger, method, start, err, fields...)
		return nil, err
	}

	logOperationSuccess(logger, method, start, zap.String("user_profile_id", result.UserProfile.ID.String()))
	return result, nil
}
