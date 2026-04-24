package handler

import (
	authv1 "auth/auth/v1"
	"context"
)

type AuthHandler struct {
	authv1.UnimplementedAuthServiceServer
}

func NewAuthHandler() *AuthHandler {
	return &AuthHandler{}
}

func (h *AuthHandler) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	// тут будет бизнес-логика
	return &authv1.RegisterResponse{}, nil
}
func (h *AuthHandler) Login(ctx context.Context, request *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	// тут будет бизнес-логика
	return &authv1.LoginResponse{}, nil
}

func (h *AuthHandler) Logout(ctx context.Context, request *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	// тут будет бизнес-логика
	return &authv1.LogoutResponse{}, nil
}

func (h *AuthHandler) Refresh(ctx context.Context, request *authv1.RefreshRequest) (*authv1.RefreshResponse, error) {
	// тут будет бизнес-логика
	return &authv1.RefreshResponse{}, nil
}

func (h *AuthHandler) LogoutAll(ctx context.Context, request *authv1.LogoutAllRequest) (*authv1.LogoutAllResponse, error) {
	// тут будет бизнес-логика
	return &authv1.LogoutAllResponse{}, nil
}

func (h *AuthHandler) GetUserAuthInfo(ctx context.Context, request *authv1.GetUserAuthInfoRequest) (*authv1.GetUserAuthInfoResponse, error) {
	return &authv1.GetUserAuthInfoResponse{}, nil
}

func (h *AuthHandler) GetJWKS(ctx context.Context, request *authv1.GetJWKSRequest) (*authv1.GetJWKSResponse, error) {
	return &authv1.GetJWKSResponse{}, nil
}
