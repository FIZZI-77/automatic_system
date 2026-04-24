package service

import (
	"auth/models"
	"auth/src/core/repository"
	"context"
	"github.com/google/uuid"
)

const salt = "dfg4124321jndfsglorprmupgreuhg"

type AuthServiceStruct struct {
	repo *repository.Repo
}

func NewAuthServiceStruct(repo *repository.Repo) *AuthServiceStruct {
	return &AuthServiceStruct{repo: repo}
}

func (a *AuthServiceStruct) Register(ctx context.Context, in models.RegisterInput) (*models.RegisterResult, error) {

}

func (a *AuthServiceStruct) Login(ctx context.Context, in models.LoginInput) (*models.LoginResult, error) {

}

func (a *AuthServiceStruct) Refresh(ctx context.Context, in models.RefreshInput) (*models.RefreshResult, error) {

}

func (a *AuthServiceStruct) Logout(ctx context.Context, in models.LogoutInput) error {

}

func (a *AuthServiceStruct) LogoutAll(ctx context.Context, in models.LogoutAllInput) (uint32, error) {

}

func (a *AuthServiceStruct) GetUserAuthInfo(ctx context.Context, userID uuid.UUID) (*models.UserAuthInfo, error) {

}

func (a *AuthServiceStruct) GetJWKS(ctx context.Context) (string, error) {

}

func (s *AuthServiceStruct) generateAccessToken(userID uuid.UUID, sessionID uuid.UUID, email string) (string, int64, error) {
	// генерация JWT
}

func (s *AuthServiceStruct) generateRefreshToken() (raw string, hash string, err error) {
	// генерация refresh token и его hash
}
