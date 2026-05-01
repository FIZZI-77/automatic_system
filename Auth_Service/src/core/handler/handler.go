package handler

import (
	authv1 "auth/auth/v1"
	"auth/models"
	"auth/src/core/service"
	"context"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

type AuthHandler struct {
	authv1.UnimplementedAuthServiceServer
	service *service.Service
	logger  *zap.Logger
}

func NewAuthHandler(ser *service.Service, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		service: ser,
		logger:  logger,
	}
}

func (h *AuthHandler) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {

	start := time.Now()

	h.logger.Info("gRPC request received",
		zap.String("method", "Register"),
		zap.String("email", req.GetEmail()),
		zap.String("username", req.GetUsername()),
	)

	registerInput := models.RegisterInput{
		Username: req.GetUsername(),
		Password: req.GetPassword(),
		Email:    req.GetEmail(),
	}

	result, err := h.service.Register(ctx, registerInput)

	if err != nil {
		h.logger.Warn("gRPC request failed",
			zap.String("method", "Register"),
			zap.Duration("duration", time.Since(start)),
			zap.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed register: %v", err)
	}

	h.logger.Info("gRPC request succeeded",
		zap.String("method", "Register"),
		zap.Duration("duration", time.Since(start)),
		zap.String("user_id", result.UserID),
		zap.String("email", result.Email),
	)

	registerResponse := &authv1.RegisterResponse{
		UserId:        result.UserID,
		Email:         result.Email,
		EmailVerified: result.EmailVerified,
	}

	return registerResponse, nil

}
func (h *AuthHandler) Login(ctx context.Context, request *authv1.LoginRequest) (*authv1.LoginResponse, error) {

	start := time.Now()

	h.logger.Info("gRPC request",
		zap.String("method", "Login"),
		zap.String("email", request.GetEmail()),
		zap.String("client_id", request.GetClientId()),
		zap.String("ip", request.GetIp()),
		zap.String("user_agent", request.GetUserAgent()),
	)

	loginInput := models.LoginInput{
		Email:     request.GetEmail(),
		Password:  request.GetPassword(),
		ClientID:  request.GetClientId(),
		IP:        request.GetIp(),
		UserAgent: request.GetUserAgent(),
	}

	result, err := h.service.Login(ctx, loginInput)

	if err != nil {
		h.logger.Warn("gRPC request failed",
			zap.String("method", "Login"),
			zap.String("email", request.GetEmail()),
			zap.Duration("duration", time.Since(start)),
			zap.String("error", err.Error()),
		)
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

	h.logger.Info("gRPC request succeeded",
		zap.String("method", "Login"),
		zap.String("email", request.GetEmail()),
		zap.String("session_id", result.SessionID.String()),
		zap.Duration("duration", time.Since(start)),
	)

	return loginResponse, nil
}

func (h *AuthHandler) Logout(ctx context.Context, request *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {

	start := time.Now()

	userID, err := uuid.Parse(request.GetUserId())
	if err != nil {
		h.logger.Warn("invalid user_id in request",
			zap.String("method", "Logout"),
			zap.String("user_id", request.GetUserId()),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	sessionID, err := uuid.Parse(request.GetSessionId())
	if err != nil {
		h.logger.Warn("invalid session_id in request",
			zap.String("method", "Logout"),
			zap.String("session_id", request.GetSessionId()),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.InvalidArgument, "invalid session_id: %v", err)
	}

	logoutInput := models.LogoutInput{
		UserID:    userID,
		SessionID: sessionID,
	}

	err = h.service.Logout(ctx, logoutInput)
	if err != nil {
		h.logger.Warn("gRPC request failed",
			zap.String("method", "Logout"),
			zap.String("user_id", userID.String()),
			zap.String("session_id", sessionID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "failed Logout: %v", err)
	}

	h.logger.Info("gRPC request succeeded",
		zap.String("method", "Logout"),
		zap.String("user_id", userID.String()),
		zap.String("session_id", sessionID.String()),
		zap.Duration("duration", time.Since(start)),
	)

	logoutResponse := &authv1.LogoutResponse{
		Success: true,
	}

	return logoutResponse, nil
}

func (h *AuthHandler) Refresh(ctx context.Context, request *authv1.RefreshRequest) (*authv1.RefreshResponse, error) {
	start := time.Now()

	h.logger.Info("gRPC request received",
		zap.String("method", "Refresh"),
		zap.Bool("has_refresh_token", request.GetRefreshToken() != ""),
		zap.String("client_id", request.GetClientId()),
		zap.String("ip", request.GetIp()),
	)

	refreshInput := models.RefreshInput{
		RefreshToken: request.GetRefreshToken(),
		ClientID:     request.GetClientId(),
		IP:           request.GetIp(),
		UserAgent:    request.GetUserAgent(),
	}

	result, err := h.service.Refresh(ctx, refreshInput)
	if err != nil {
		h.logger.Info("gRPC request received",
			zap.String("method", "Refresh"),
			zap.Bool("has_refresh_token", request.GetRefreshToken() != ""),
			zap.String("client_id", request.GetClientId()),
			zap.String("ip", request.GetIp()),
		)
		return nil, status.Errorf(codes.Internal, "failed Refresh: %v", err)
	}

	h.logger.Info("gRPC request succeeded",
		zap.String("method", "Refresh"),
		zap.String("session_id", result.SessionID.String()),
		zap.Duration("duration", time.Since(start)),
	)

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

	start := time.Now()

	h.logger.Info("gRPC request received",
		zap.String("method", "LogoutAll"),
		zap.String("user_id", request.GetUserId()),
	)

	userID, err := uuid.Parse(request.GetUserId())
	if err != nil {
		h.logger.Warn("invalid user_id in request",
			zap.String("method", "LogoutAll"),
			zap.String("user_id", request.GetUserId()),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	logoutInput := models.LogoutAllInput{
		UserID: userID,
	}

	result, err := h.service.LogoutAll(ctx, logoutInput)
	if err != nil {
		h.logger.Warn("gRPC request failed",
			zap.String("method", "LogoutAll"),
			zap.String("user_id", userID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "failed LogoutAll: %v", err)
	}

	logoutResponse := &authv1.LogoutAllResponse{
		Success:      true,
		RevokedCount: result,
	}

	h.logger.Info("gRPC request succeeded",
		zap.String("method", "LogoutAll"),
		zap.String("user_id", userID.String()),
		zap.Uint32("revoked_count", result),
		zap.Duration("duration", time.Since(start)),
	)

	return logoutResponse, nil
}

func (h *AuthHandler) GetUserAuthInfo(ctx context.Context, request *authv1.GetUserAuthInfoRequest) (*authv1.GetUserAuthInfoResponse, error) {
	start := time.Now()

	h.logger.Info("gRPC request received",
		zap.String("method", "GetUserAuthInfo"),
		zap.String("user_id", request.GetUserId()),
	)

	userID, err := uuid.Parse(request.GetUserId())
	if err != nil {
		h.logger.Warn("invalid user_id in request",
			zap.String("method", "GetUserAuthInfo"),
			zap.String("user_id", request.GetUserId()),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	user, err := h.service.GetUserAuthInfo(ctx, userID)
	if err != nil {
		h.logger.Warn("gRPC request failed",
			zap.String("method", "GetUserAuthInfo"),
			zap.String("user_id", userID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "failed GetUserAuthInfo: %v", err)
	}

	h.logger.Info("gRPC request succeeded",
		zap.String("method", "GetUserAuthInfo"),
		zap.String("user_id", userID.String()),
		zap.String("email", user.Email),
		zap.Int("roles_count", len(user.Roles)),
		zap.Bool("is_active", user.IsActive),
		zap.Bool("email_verified", user.EmailVerified),
		zap.Duration("duration", time.Since(start)),
	)

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
	start := time.Now()

	h.logger.Info("gRPC request received",
		zap.String("method", "GetJWKS"),
	)

	jwk, err := h.service.GetJWKS(ctx)

	if err != nil {
		h.logger.Warn("gRPC request failed",
			zap.String("method", "GetJWKS"),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "failed GetJWKS: %v", err)
	}

	h.logger.Info("gRPC request succeeded",
		zap.String("method", "GetJWKS"),
		zap.Int("jwks_size", len(jwk)),
		zap.Duration("duration", time.Since(start)),
	)

	jWKSResponse := &authv1.GetJWKSResponse{
		JwksJson: jwk,
	}
	return jWKSResponse, nil
}

func (h *AuthHandler) ChangePassword(ctx context.Context, request *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {
	start := time.Now()

	h.logger.Info("gRPC request received",
		zap.String("method", "ChangePassword"),
		zap.String("user_id", request.GetUserId()),
		zap.String("session_id", request.GetSessionId()),
		zap.Bool("revoke_other_sessions", request.GetRevokeOtherSessions()),
	)

	userID, err := uuid.Parse(request.GetUserId())
	if err != nil {
		h.logger.Warn("invalid user_id in request",
			zap.String("method", "ChangePassword"),
			zap.String("user_id", request.GetUserId()),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	sessionID, err := uuid.Parse(request.GetSessionId())
	if err != nil {
		h.logger.Warn("invalid session_id in request",
			zap.String("method", "ChangePassword"),
			zap.String("session_id", request.GetSessionId()),
			zap.Error(err),
		)
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
		h.logger.Warn("gRPC request failed",
			zap.String("method", "ChangePassword"),
			zap.String("user_id", userID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "failed ChangePassword: %v", err)
	}

	h.logger.Info("gRPC request succeeded",
		zap.String("method", "ChangePassword"),
		zap.String("user_id", userID.String()),
		zap.Int32("invalidated_sessions_count", out.InvalidatedSessionsCount),
		zap.Duration("duration", time.Since(start)),
	)

	response := &authv1.ChangePasswordResponse{
		Success:                  out.Success,
		InvalidatedSessionsCount: uint32(out.InvalidatedSessionsCount),
	}

	return response, nil
}

func (h *AuthHandler) SendVerificationEmail(ctx context.Context, request *authv1.SendVerificationEmailRequest) (*authv1.SendVerificationEmailResponse, error) {
	start := time.Now()

	h.logger.Info("gRPC request received",
		zap.String("method", "SendVerificationEmail"),
		zap.String("user_id", request.GetUserId()),
		zap.String("email", request.GetEmail()),
	)

	userID, err := uuid.Parse(request.GetUserId())
	if err != nil {
		h.logger.Warn("invalid user_id in request",
			zap.String("method", "SendVerificationEmail"),
			zap.String("user_id", request.GetUserId()),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	input := models.SendVerificationEmailInput{
		UserID: userID,
		Email:  request.GetEmail(),
	}

	out, err := h.service.SendVerification(ctx, input)
	if err != nil {
		h.logger.Warn("gRPC request failed",
			zap.String("method", "SendVerificationEmail"),
			zap.String("user_id", userID.String()),
			zap.String("email", request.GetEmail()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "failed SendVerificationEmail: %v", err)
	}

	h.logger.Info("gRPC request succeeded",
		zap.String("method", "SendVerificationEmail"),
		zap.String("user_id", userID.String()),
		zap.String("email", request.GetEmail()),
		zap.Int64("expires_at_unix", out.ExpiresAtUnix),
		zap.Duration("duration", time.Since(start)),
	)

	response := &authv1.SendVerificationEmailResponse{
		Success:       out.Success,
		ExpiresAtUnix: out.ExpiresAtUnix,
	}
	return response, nil
}

func (h *AuthHandler) VerifyEmail(ctx context.Context, request *authv1.VerifyEmailRequest) (*authv1.VerifyEmailResponse, error) {
	start := time.Now()

	h.logger.Info("gRPC request received",
		zap.String("method", "VerifyEmail"),
		zap.Bool("has_token", request.GetToken() != ""),
	)

	input := models.VerifyEmailInput{
		Token: request.GetToken(),
	}

	out, err := h.service.VerifyEmail(ctx, input)
	if err != nil {
		h.logger.Warn("gRPC request failed",
			zap.String("method", "VerifyEmail"),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "failed VerifyEmail: %v", err)
	}

	h.logger.Info("gRPC request succeeded",
		zap.String("method", "VerifyEmail"),
		zap.String("user_id", out.UserID.String()),
		zap.String("email", out.Email),
		zap.Bool("email_verified", out.EmailVerified),
		zap.Duration("duration", time.Since(start)),
	)

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
	start := time.Now()

	h.logger.Info("gRPC request received",
		zap.String("method", "RequestPasswordReset"),
		zap.String("email", request.GetEmail()),
	)

	input := models.RequestPasswordResetInput{
		Email: request.GetEmail(),
	}

	out, err := h.service.RequestPasswordReset(ctx, input)
	if err != nil {
		h.logger.Warn("gRPC request failed",
			zap.String("method", "RequestPasswordReset"),
			zap.String("email", request.GetEmail()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "failed RequestPasswordReset: %v", err)
	}

	h.logger.Info("gRPC request succeeded",
		zap.String("method", "RequestPasswordReset"),
		zap.String("email", request.GetEmail()),
		zap.Bool("email_exists", out.ExpiresAtUnix != 0),
		zap.Int64("expires_at_unix", out.ExpiresAtUnix),
		zap.Duration("duration", time.Since(start)),
	)

	response := &authv1.RequestPasswordResetResponse{
		Success:       out.Success,
		ExpiresAtUnix: out.ExpiresAtUnix,
	}

	return response, nil
}

func (h *AuthHandler) ResetPassword(ctx context.Context, request *authv1.ResetPasswordRequest) (*authv1.ResetPasswordResponse, error) {
	start := time.Now()

	h.logger.Info("gRPC request received",
		zap.String("method", "ResetPassword"),
		zap.Bool("has_token", request.GetToken() != ""),
	)

	input := models.ResetPasswordInput{
		Token:       request.GetToken(),
		NewPassword: request.GetNewPassword(),
	}

	out, err := h.service.ResetPassword(ctx, input)
	if err != nil {
		h.logger.Warn("gRPC request failed",
			zap.String("method", "ResetPassword"),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "failed ResetPassword: %v", err)
	}

	h.logger.Info("gRPC request succeeded",
		zap.String("method", "ResetPassword"),
		zap.Uint32("invalidated_sessions_count", uint32(out.InvalidatedSessionsCount)),
		zap.Duration("duration", time.Since(start)),
	)

	response := &authv1.ResetPasswordResponse{
		Success:                  out.Success,
		InvalidatedSessionsCount: uint32(out.InvalidatedSessionsCount),
	}

	return response, nil
}
