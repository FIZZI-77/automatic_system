package service

import (
	"auth/models"
	"auth/src/core/repository"
	"context"
	"crypto/rsa"
	"github.com/google/uuid"
)

type AuthService interface {
	Register(ctx context.Context, in models.RegisterInput) (*models.RegisterResult, error)
	Login(ctx context.Context, in models.LoginInput) (*models.LoginResult, error)
	Refresh(ctx context.Context, in models.RefreshInput) (*models.RefreshResult, error)
	Logout(ctx context.Context, in models.LogoutInput) error
	LogoutAll(ctx context.Context, in models.LogoutAllInput) (uint32, error)
	GetUserAuthInfo(ctx context.Context, userID uuid.UUID) (*models.UserAuthInfo, error)
	GetJWKS(ctx context.Context) (string, error)

	ChangePassword(ctx context.Context, in models.ChangePasswordInput) (*models.ChangePasswordResult, error)
	VerifyEmail(ctx context.Context, in models.VerifyEmailInput) (*models.VerifyEmailResult, error)
	RequestPasswordReset(ctx context.Context, in models.RequestPasswordResetInput) (*models.RequestPasswordResetResult, error)
	ResetPassword(ctx context.Context, in models.ResetPasswordInput) (*models.ResetPasswordResult, error)
	SendVerification(ctx context.Context, in models.SendVerificationEmailInput) (*models.SendVerificationEmailResult, error)
}

type MailService interface {
	SendVerificationEmail(ctx context.Context, toEmail string, token string) error
	SendPasswordResetEmail(ctx context.Context, toEmail string, token string) error
}
type Service struct {
	AuthService
	MailService
}

func NewAuthService(repo *repository.Repo, privateKey *rsa.PrivateKey, keyID string, mailService MailService) *Service {
	return &Service{
		AuthService: NewAuthServiceStruct(repo, privateKey, keyID, mailService),
	}
}
