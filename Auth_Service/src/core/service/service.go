package service

import (
	"context"
	"crypto/rsa"

	"auth/models"
	"auth/src/core/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AuthService interface {
	// Register создаёт учётную запись, обеспечивает личный профиль и отправляет подтверждение почты.
	Register(ctx context.Context, in models.RegisterInput) (*models.RegisterResult, error)
	// Login проверяет пароль и активность пользователя, создаёт сессию и выдаёт пару токенов.
	Login(ctx context.Context, in models.LoginInput) (*models.LoginResult, error)
	// Refresh проверяет refresh-токен и сессию и заменяет токен новой парой.
	Refresh(ctx context.Context, in models.RefreshInput) (*models.RefreshResult, error)
	// Logout отзывает указанную сессию пользователя и её refresh-токены.
	Logout(ctx context.Context, in models.LogoutInput) error
	// LogoutAll отзывает сессии пользователя и возвращает количество закрытых сессий.
	LogoutAll(ctx context.Context, in models.LogoutAllInput) (uint32, error)
	// GetUserAuthInfo возвращает учётные сведения и роли пользователя по его UUID.
	GetUserAuthInfo(ctx context.Context, userID uuid.UUID) (*models.UserAuthInfo, error)
	// GetJWKS возвращает JSON-набор открытых ключей для проверки подписей JWT.
	GetJWKS(ctx context.Context) (string, error)

	// ChangePassword проверяет старый пароль, сохраняет новый хеш и отзывает текущую либо все сессии.
	ChangePassword(ctx context.Context, in models.ChangePasswordInput) (*models.ChangePasswordResult, error)
	// VerifyEmail подтверждает почту по действующему одноразовому токену.
	VerifyEmail(ctx context.Context, in models.VerifyEmailInput) (*models.VerifyEmailResult, error)
	// RequestPasswordReset запрашивает письмо со ссылкой сброса пароля по адресу почты.
	RequestPasswordReset(ctx context.Context, in models.RequestPasswordResetInput) (*models.RequestPasswordResetResult, error)
	// ResetPassword устанавливает новый пароль по действующему одноразовому токену.
	ResetPassword(ctx context.Context, in models.ResetPasswordInput) (*models.ResetPasswordResult, error)
	// SendVerification создаёт одноразовый токен и отправляет письмо подтверждения пользователю.
	SendVerification(ctx context.Context, in models.SendVerificationEmailInput) (*models.SendVerificationEmailResult, error)
}

type MailService interface {
	// SendVerificationEmail отправляет адресату ссылку подтверждения с переданным токеном.
	SendVerificationEmail(ctx context.Context, toEmail string, token string) error
	// SendPasswordResetEmail отправляет адресату ссылку сброса с переданным токеном.
	SendPasswordResetEmail(ctx context.Context, toEmail string, token string) error
}

type ProfileProvisioner interface {
	// CreateUserProfile обеспечивает создание личного профиля для новой учётной записи.
	CreateUserProfile(ctx context.Context, userID uuid.UUID, fullName string) error
	// UserProfileExists проверяет наличие личного профиля по идентификатору учётной записи.
	UserProfileExists(ctx context.Context, userID uuid.UUID) (bool, error)
}
type Service struct {
	AuthService
	MailService
}

// NewService объединяет аутентификацию и отправку писем с переданными зависимостями.
// При nil-журнале использует zap.NewNop; приватный ключ предназначен для подписи JWT.
func NewService(
	repo *repository.Repository,
	privateKey *rsa.PrivateKey,
	keyID string,
	mailService MailService,
	profileProvisioner ProfileProvisioner,
	logger *zap.Logger,
) *Service {

	if logger == nil {
		logger = zap.NewNop()
	}

	return &Service{
		AuthService: NewAuthServiceStruct(
			repo,
			privateKey,
			keyID,
			mailService,
			profileProvisioner,
			logger,
		),
		MailService: mailService,
	}
}

// NewAuthService вызывает NewService и сохраняет совместимость прежних вызовов конструктора.
func NewAuthService(
	repo *repository.Repo,
	privateKey *rsa.PrivateKey,
	keyID string,
	mailService MailService,
	profileProvisioner ProfileProvisioner,
	logger *zap.Logger,
) *Service {
	return NewService(repo, privateKey, keyID, mailService, profileProvisioner, logger)
}
