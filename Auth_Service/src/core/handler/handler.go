package handler

import (
	authv1 "auth/auth/v1"
	"auth/models"
	"auth/src/core/service"
	"context"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthHandler struct {
	authv1.UnimplementedAuthServiceServer
	service service.AuthService
}

func NewAuthHandler(ser service.AuthService) *AuthHandler {
	return &AuthHandler{
		service: ser,
	}
}

func (h *AuthHandler) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	registerInput := models.RegisterInput{
		Username: req.GetUsername(),
		Password: req.GetPassword(),
		Email:    req.GetEmail(),
	}

	result, err := h.service.Register(ctx, registerInput)

	if err != nil {

		return nil, status.Errorf(codes.Internal, "failed register: %v", err)
	}

	registerResponse := &authv1.RegisterResponse{
		UserId:        result.UserID,
		Email:         result.Email,
		EmailVerified: result.EmailVerified,
	}
	return registerResponse, nil

}
func (h *AuthHandler) Login(ctx context.Context, request *authv1.LoginRequest) (*authv1.LoginResponse, error) {

	loginInput := models.LoginInput{
		Email:     request.GetEmail(),
		Password:  request.GetPassword(),
		ClientID:  request.GetClientId(),
		IP:        request.GetIp(),
		UserAgent: request.GetUserAgent(),
	}

	result, err := h.service.Login(ctx, loginInput)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed Login: %v", err)
	}

	loginResponse := &authv1.LoginResponse{
		AccessToken:          result.AccessToken,
		RefreshToken:         result.RefreshToken,
		AccessExpiresAtUnix:  result.AccessExpiresAtUnix,
		RefreshExpiresAtUnix: result.RefreshExpiresAtUnix,
		SessionId:            result.SessionID.String(),
		TokenType:            result.TokenType,
	}

	return loginResponse, nil
}

func (h *AuthHandler) Logout(ctx context.Context, request *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {

	userID, err := uuid.Parse(request.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	sessionID, err := uuid.Parse(request.GetSessionId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session_id: %v", err)
	}

	logoutInput := models.LogoutInput{
		UserID:    userID,
		SessionID: sessionID,
	}

	err = h.service.Logout(ctx, logoutInput)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed Logout: %v", err)
	}

	logoutResponse := &authv1.LogoutResponse{
		Success: true,
	}

	return logoutResponse, nil
}

func (h *AuthHandler) Refresh(ctx context.Context, request *authv1.RefreshRequest) (*authv1.RefreshResponse, error) {

	refreshInput := models.RefreshInput{
		RefreshToken: request.GetRefreshToken(),
		ClientID:     request.GetClientId(),
		IP:           request.GetIp(),
		UserAgent:    request.GetUserAgent(),
	}

	result, err := h.service.Refresh(ctx, refreshInput)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed Refresh: %v", err)
	}

	refreshResponse := &authv1.RefreshResponse{
		AccessToken:          result.AccessToken,
		RefreshToken:         result.RefreshToken,
		AccessExpiresAtUnix:  result.AccessExpiresAtUnix,
		RefreshExpiresAtUnix: result.RefreshExpiresAtUnix,
		SessionId:            result.SessionID.String(),
		TokenType:            result.TokenType,
	}

	return refreshResponse, nil
}

func (h *AuthHandler) LogoutAll(ctx context.Context, request *authv1.LogoutAllRequest) (*authv1.LogoutAllResponse, error) {

	userID, err := uuid.Parse(request.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	logoutInput := models.LogoutAllInput{
		UserID: userID,
	}

	result, err := h.service.LogoutAll(ctx, logoutInput)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed LogoutAll: %v", err)
	}

	logoutResponse := &authv1.LogoutAllResponse{
		Success:      true,
		RevokedCount: result,
	}

	return logoutResponse, nil
}

func (h *AuthHandler) GetUserAuthInfo(ctx context.Context, request *authv1.GetUserAuthInfoRequest) (*authv1.GetUserAuthInfoResponse, error) {

	userID, err := uuid.Parse(request.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	user, err := h.service.GetUserAuthInfo(ctx, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed GetUserAuthInfo: %v", err)
	}

	userAuthInfo := &authv1.GetUserAuthInfoResponse{
		UserId:        user.UserID.String(),
		Email:         user.Email,
		Roles:         user.Roles,
		Permissions:   user.Permissions,
		IsActive:      user.IsActive,
		EmailVerified: user.EmailVerified,
	}

	return userAuthInfo, nil
}

func (h *AuthHandler) GetJWKS(ctx context.Context, request *authv1.GetJWKSRequest) (*authv1.GetJWKSResponse, error) {

	jwk, err := h.service.GetJWKS(ctx)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed GetJWKS: %v", err)
	}

	jWKSResponse := &authv1.GetJWKSResponse{
		JwksJson: jwk,
	}
	return jWKSResponse, nil
}
