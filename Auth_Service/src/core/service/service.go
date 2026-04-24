package service

import (
	"auth/models"
	"context"
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
}
type Service struct {
	AuthService
}

func NewAuthService() *Service {
	return &Service{}
}
