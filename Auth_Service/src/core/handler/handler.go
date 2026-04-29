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
	service *service.Service
}

func NewAuthHandler(ser *service.Service) *AuthHandler {
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

func (h *AuthHandler) GetJWKS(ctx context.Context, _ *authv1.GetJWKSRequest) (*authv1.GetJWKSResponse, error) {

	jwk, err := h.service.GetJWKS(ctx)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed GetJWKS: %v", err)
	}

	jWKSResponse := &authv1.GetJWKSResponse{
		JwksJson: jwk,
	}
	return jWKSResponse, nil
}

func (h *AuthHandler) ChangePassword(ctx context.Context, request *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {

	userID, err := uuid.Parse(request.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	sessionID, err := uuid.Parse(request.GetSessionId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session_id: %v", err)
	}

	input := models.ChangePasswordInput{
		UserID:              userID,
		OldPassword:         request.GetOldPassword(),
		NewPassword:         request.GetNewPassword(),
		SessionID:           sessionID,
		RevokeOtherSessions: request.GetRevokeOtherSessions(),
	}

	out, err := h.service.ChangePassword(ctx, input)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed ChangePassword: %v", err)
	}
	response := &authv1.ChangePasswordResponse{
		Success:                  out.Success,
		InvalidatedSessionsCount: uint32(out.InvalidatedSessionsCount),
	}

	return response, nil
}

func (h *AuthHandler) SendVerificationEmail(ctx context.Context, request *authv1.SendVerificationEmailRequest) (*authv1.SendVerificationEmailResponse, error) {

	userID, err := uuid.Parse(request.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	input := models.SendVerificationEmailInput{
		UserID: userID,
		Email:  request.GetEmail(),
	}

	out, err := h.service.SendVerification(ctx, input)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed SendVerificationEmail: %v", err)
	}

	response := &authv1.SendVerificationEmailResponse{
		Success:       out.Success,
		ExpiresAtUnix: out.ExpiresAtUnix,
	}
	return response, nil
}

func (h *AuthHandler) VerifyEmail(ctx context.Context, request *authv1.VerifyEmailRequest) (*authv1.VerifyEmailResponse, error) {

	input := models.VerifyEmailInput{
		Token: request.GetToken(),
	}

	out, err := h.service.VerifyEmail(ctx, input)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed VerifyEmail: %v", err)
	}

	response := &authv1.VerifyEmailResponse{
		Success:       out.Success,
		UserId:        out.UserID.String(),
		Email:         out.Email,
		EmailVerified: out.EmailVerified,
		Message:       out.Message,
	}

	return response, nil
}

func (h *AuthHandler) RequestPasswordReset(ctx context.Context, request *authv1.RequestPasswordResetRequest) (*authv1.RequestPasswordResetResponse, error) {

	input := models.RequestPasswordResetInput{
		Email: request.GetEmail(),
	}

	out, err := h.service.RequestPasswordReset(ctx, input)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed RequestPasswordReset: %v", err)
	}

	response := &authv1.RequestPasswordResetResponse{
		Success:       out.Success,
		ExpiresAtUnix: out.ExpiresAtUnix,
	}

	return response, nil
}

func (h *AuthHandler) ResetPassword(ctx context.Context, request *authv1.ResetPasswordRequest) (*authv1.ResetPasswordResponse, error) {

	input := models.ResetPasswordInput{
		Token:       request.GetToken(),
		NewPassword: request.GetNewPassword(),
	}

	out, err := h.service.ResetPassword(ctx, input)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed ResetPassword: %v", err)
	}

	response := &authv1.ResetPasswordResponse{
		Success:                  out.Success,
		InvalidatedSessionsCount: uint32(out.InvalidatedSessionsCount),
	}
	
	return response, nil
}
