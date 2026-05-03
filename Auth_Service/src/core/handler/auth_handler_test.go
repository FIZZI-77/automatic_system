package handler

import (
	authv1 "auth/auth/v1"
	"auth/models"
	"auth/src/core/service"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockAuthService struct {
	registerFunc             func(ctx context.Context, in models.RegisterInput) (*models.RegisterResult, error)
	loginFunc                func(ctx context.Context, in models.LoginInput) (*models.LoginResult, error)
	refreshFunc              func(ctx context.Context, in models.RefreshInput) (*models.RefreshResult, error)
	logoutFunc               func(ctx context.Context, in models.LogoutInput) error
	logoutAllFunc            func(ctx context.Context, in models.LogoutAllInput) (uint32, error)
	getUserAuthInfoFunc      func(ctx context.Context, userID uuid.UUID) (*models.UserAuthInfo, error)
	getJWKSFunc              func(ctx context.Context) (string, error)
	changePasswordFunc       func(ctx context.Context, in models.ChangePasswordInput) (*models.ChangePasswordResult, error)
	verifyEmailFunc          func(ctx context.Context, in models.VerifyEmailInput) (*models.VerifyEmailResult, error)
	requestPasswordResetFunc func(ctx context.Context, in models.RequestPasswordResetInput) (*models.RequestPasswordResetResult, error)
	resetPasswordFunc        func(ctx context.Context, in models.ResetPasswordInput) (*models.ResetPasswordResult, error)
	sendVerificationFunc     func(ctx context.Context, in models.SendVerificationEmailInput) (*models.SendVerificationEmailResult, error)
}

func (m *mockAuthService) Register(ctx context.Context, in models.RegisterInput) (*models.RegisterResult, error) {
	return m.registerFunc(ctx, in)
}

func (m *mockAuthService) Login(ctx context.Context, in models.LoginInput) (*models.LoginResult, error) {
	return m.loginFunc(ctx, in)
}

func (m *mockAuthService) Refresh(ctx context.Context, in models.RefreshInput) (*models.RefreshResult, error) {
	return m.refreshFunc(ctx, in)
}

func (m *mockAuthService) Logout(ctx context.Context, in models.LogoutInput) error {
	return m.logoutFunc(ctx, in)
}

func (m *mockAuthService) LogoutAll(ctx context.Context, in models.LogoutAllInput) (uint32, error) {
	return m.logoutAllFunc(ctx, in)
}

func (m *mockAuthService) GetUserAuthInfo(ctx context.Context, userID uuid.UUID) (*models.UserAuthInfo, error) {
	return m.getUserAuthInfoFunc(ctx, userID)
}

func (m *mockAuthService) GetJWKS(ctx context.Context) (string, error) {
	return m.getJWKSFunc(ctx)
}

func (m *mockAuthService) ChangePassword(ctx context.Context, in models.ChangePasswordInput) (*models.ChangePasswordResult, error) {
	return m.changePasswordFunc(ctx, in)
}

func (m *mockAuthService) VerifyEmail(ctx context.Context, in models.VerifyEmailInput) (*models.VerifyEmailResult, error) {
	return m.verifyEmailFunc(ctx, in)
}

func (m *mockAuthService) RequestPasswordReset(ctx context.Context, in models.RequestPasswordResetInput) (*models.RequestPasswordResetResult, error) {
	return m.requestPasswordResetFunc(ctx, in)
}

func (m *mockAuthService) ResetPassword(ctx context.Context, in models.ResetPasswordInput) (*models.ResetPasswordResult, error) {
	return m.resetPasswordFunc(ctx, in)
}

func (m *mockAuthService) SendVerification(ctx context.Context, in models.SendVerificationEmailInput) (*models.SendVerificationEmailResult, error) {
	return m.sendVerificationFunc(ctx, in)
}

func newTestHandler(mock *mockAuthService) *AuthHandler {
	return NewAuthHandler(&service.Service{
		AuthService: mock,
	}, zap.NewNop())
}

func assertGRPCCode(t *testing.T, err error, expected codes.Code) {
	t.Helper()

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status error, got %v", err)
	}

	if st.Code() != expected {
		t.Fatalf("expected grpc code %v, got %v", expected, st.Code())
	}
}

func TestAuthHandler_Register_Success(t *testing.T) {
	mock := &mockAuthService{
		registerFunc: func(ctx context.Context, in models.RegisterInput) (*models.RegisterResult, error) {
			if in.Email != "test@example.com" {
				t.Fatalf("expected email test@example.com, got %s", in.Email)
			}

			if in.Username != "testuser" {
				t.Fatalf("expected username testuser, got %s", in.Username)
			}

			if in.Password != "password123" {
				t.Fatalf("expected password password123, got %s", in.Password)
			}

			return &models.RegisterResult{
				UserID:        "user-id",
				Email:         in.Email,
				EmailVerified: false,
			}, nil
		},
	}

	h := newTestHandler(mock)

	resp, err := h.Register(context.Background(), &authv1.RegisterRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if resp.GetUserId() != "user-id" {
		t.Fatalf("expected user-id, got %s", resp.GetUserId())
	}

	if resp.GetEmail() != "test@example.com" {
		t.Fatalf("expected test@example.com, got %s", resp.GetEmail())
	}

	if resp.GetEmailVerified() {
		t.Fatal("expected email_verified false")
	}
}

func TestAuthHandler_Register_ServiceError(t *testing.T) {
	mock := &mockAuthService{
		registerFunc: func(ctx context.Context, in models.RegisterInput) (*models.RegisterResult, error) {
			return nil, errors.New("register error")
		},
	}

	h := newTestHandler(mock)

	resp, err := h.Register(context.Background(), &authv1.RegisterRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
	})

	if resp != nil {
		t.Fatal("expected nil response")
	}

	assertGRPCCode(t, err, codes.Internal)
}

func TestAuthHandler_Login_Success(t *testing.T) {
	sessionID := uuid.New()

	mock := &mockAuthService{
		loginFunc: func(ctx context.Context, in models.LoginInput) (*models.LoginResult, error) {
			if in.Email != "test@example.com" {
				t.Fatalf("expected email test@example.com, got %s", in.Email)
			}

			if in.Password != "password123" {
				t.Fatalf("expected password password123, got %s", in.Password)
			}

			if in.ClientID != "web-client" {
				t.Fatalf("expected client_id web-client, got %s", in.ClientID)
			}

			if in.IP != "127.0.0.1" {
				t.Fatalf("expected ip 127.0.0.1, got %s", in.IP)
			}

			if in.UserAgent != "Mozilla/5.0" {
				t.Fatalf("expected user agent Mozilla/5.0, got %s", in.UserAgent)
			}

			return &models.LoginResult{
				AccessToken:          "access-token",
				RefreshToken:         "refresh-token",
				AccessExpiresAtUnix:  100,
				RefreshExpiresAtUnix: 200,
				SessionID:            sessionID,
				TokenType:            "Bearer",
			}, nil
		},
	}

	h := newTestHandler(mock)

	resp, err := h.Login(context.Background(), &authv1.LoginRequest{
		Email:     "test@example.com",
		Password:  "password123",
		ClientId:  "web-client",
		Ip:        "127.0.0.1",
		UserAgent: "Mozilla/5.0",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if resp.GetAccessToken() != "access-token" {
		t.Fatalf("expected access-token, got %s", resp.GetAccessToken())
	}

	if resp.GetRefreshToken() != "refresh-token" {
		t.Fatalf("expected refresh-token, got %s", resp.GetRefreshToken())
	}

	if resp.GetSessionId() != sessionID.String() {
		t.Fatalf("expected session_id %s, got %s", sessionID.String(), resp.GetSessionId())
	}

	if resp.GetTokenType() != "Bearer" {
		t.Fatalf("expected Bearer, got %s", resp.GetTokenType())
	}
}

func TestAuthHandler_Login_ServiceError(t *testing.T) {
	mock := &mockAuthService{
		loginFunc: func(ctx context.Context, in models.LoginInput) (*models.LoginResult, error) {
			return nil, errors.New("login error")
		},
	}

	h := newTestHandler(mock)

	resp, err := h.Login(context.Background(), &authv1.LoginRequest{
		Email:     "test@example.com",
		Password:  "wrong-password",
		ClientId:  "web-client",
		Ip:        "127.0.0.1",
		UserAgent: "Mozilla/5.0",
	})

	if resp != nil {
		t.Fatal("expected nil response")
	}

	assertGRPCCode(t, err, codes.Internal)
}

func TestAuthHandler_Refresh_Success(t *testing.T) {
	sessionID := uuid.New()

	mock := &mockAuthService{
		refreshFunc: func(ctx context.Context, in models.RefreshInput) (*models.RefreshResult, error) {
			if in.RefreshToken != "old-refresh-token" {
				t.Fatalf("expected refresh token old-refresh-token, got %s", in.RefreshToken)
			}

			if in.ClientID != "web-client" {
				t.Fatalf("expected client_id web-client, got %s", in.ClientID)
			}

			if in.IP != "127.0.0.1" {
				t.Fatalf("expected ip 127.0.0.1, got %s", in.IP)
			}

			if in.UserAgent != "Mozilla/5.0" {
				t.Fatalf("expected user agent Mozilla/5.0, got %s", in.UserAgent)
			}

			return &models.RefreshResult{
				AccessToken:          "new-access-token",
				RefreshToken:         "new-refresh-token",
				AccessExpiresAtUnix:  300,
				RefreshExpiresAtUnix: 400,
				SessionID:            sessionID,
				TokenType:            "Bearer",
			}, nil
		},
	}

	h := newTestHandler(mock)

	resp, err := h.Refresh(context.Background(), &authv1.RefreshRequest{
		RefreshToken: "old-refresh-token",
		ClientId:     "web-client",
		Ip:           "127.0.0.1",
		UserAgent:    "Mozilla/5.0",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if resp.GetAccessToken() != "new-access-token" {
		t.Fatalf("expected new-access-token, got %s", resp.GetAccessToken())
	}

	if resp.GetRefreshToken() != "new-refresh-token" {
		t.Fatalf("expected new-refresh-token, got %s", resp.GetRefreshToken())
	}

	if resp.GetSessionId() != sessionID.String() {
		t.Fatalf("expected session_id %s, got %s", sessionID.String(), resp.GetSessionId())
	}
}

func TestAuthHandler_Refresh_ServiceError(t *testing.T) {
	mock := &mockAuthService{
		refreshFunc: func(ctx context.Context, in models.RefreshInput) (*models.RefreshResult, error) {
			return nil, errors.New("refresh error")
		},
	}

	h := newTestHandler(mock)

	resp, err := h.Refresh(context.Background(), &authv1.RefreshRequest{
		RefreshToken: "bad-refresh-token",
		ClientId:     "web-client",
		Ip:           "127.0.0.1",
		UserAgent:    "Mozilla/5.0",
	})

	if resp != nil {
		t.Fatal("expected nil response")
	}

	assertGRPCCode(t, err, codes.Internal)
}

func TestAuthHandler_Logout_Success(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	mock := &mockAuthService{
		logoutFunc: func(ctx context.Context, in models.LogoutInput) error {
			if in.UserID != userID {
				t.Fatalf("expected user_id %s, got %s", userID.String(), in.UserID.String())
			}

			if in.SessionID != sessionID {
				t.Fatalf("expected session_id %s, got %s", sessionID.String(), in.SessionID.String())
			}

			return nil
		},
	}

	h := newTestHandler(mock)

	resp, err := h.Logout(context.Background(), &authv1.LogoutRequest{
		UserId:    userID.String(),
		SessionId: sessionID.String(),
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !resp.GetSuccess() {
		t.Fatal("expected success true")
	}
}

func TestAuthHandler_Logout_InvalidUserID(t *testing.T) {
	h := newTestHandler(&mockAuthService{})

	resp, err := h.Logout(context.Background(), &authv1.LogoutRequest{
		UserId:    "bad-user-id",
		SessionId: uuid.New().String(),
	})

	if resp != nil {
		t.Fatal("expected nil response")
	}

	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestAuthHandler_Logout_InvalidSessionID(t *testing.T) {
	h := newTestHandler(&mockAuthService{})

	resp, err := h.Logout(context.Background(), &authv1.LogoutRequest{
		UserId:    uuid.New().String(),
		SessionId: "bad-session-id",
	})

	if resp != nil {
		t.Fatal("expected nil response")
	}

	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestAuthHandler_LogoutAll_Success(t *testing.T) {
	userID := uuid.New()

	mock := &mockAuthService{
		logoutAllFunc: func(ctx context.Context, in models.LogoutAllInput) (uint32, error) {
			if in.UserID != userID {
				t.Fatalf("expected user_id %s, got %s", userID.String(), in.UserID.String())
			}

			return 3, nil
		},
	}

	h := newTestHandler(mock)

	resp, err := h.LogoutAll(context.Background(), &authv1.LogoutAllRequest{
		UserId: userID.String(),
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !resp.GetSuccess() {
		t.Fatal("expected success true")
	}

	if resp.GetRevokedCount() != 3 {
		t.Fatalf("expected revoked_count 3, got %d", resp.GetRevokedCount())
	}
}

func TestAuthHandler_LogoutAll_InvalidUserID(t *testing.T) {
	h := newTestHandler(&mockAuthService{})

	resp, err := h.LogoutAll(context.Background(), &authv1.LogoutAllRequest{
		UserId: "bad-user-id",
	})

	if resp != nil {
		t.Fatal("expected nil response")
	}

	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestAuthHandler_GetUserAuthInfo_Success(t *testing.T) {
	userID := uuid.New()

	mock := &mockAuthService{
		getUserAuthInfoFunc: func(ctx context.Context, id uuid.UUID) (*models.UserAuthInfo, error) {
			if id != userID {
				t.Fatalf("expected user_id %s, got %s", userID.String(), id.String())
			}

			return &models.UserAuthInfo{
				UserID:        userID,
				Email:         "test@example.com",
				Roles:         []string{"user", "admin"},
				Permissions:   []string{"read", "write"},
				IsActive:      true,
				EmailVerified: true,
			}, nil
		},
	}

	h := newTestHandler(mock)

	resp, err := h.GetUserAuthInfo(context.Background(), &authv1.GetUserAuthInfoRequest{
		UserId: userID.String(),
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if resp.GetUserId() != userID.String() {
		t.Fatalf("expected user_id %s, got %s", userID.String(), resp.GetUserId())
	}

	if resp.GetEmail() != "test@example.com" {
		t.Fatalf("expected test@example.com, got %s", resp.GetEmail())
	}

	if len(resp.GetRoles()) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(resp.GetRoles()))
	}

	if len(resp.GetPermissions()) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(resp.GetPermissions()))
	}

	if !resp.GetIsActive() {
		t.Fatal("expected is_active true")
	}

	if !resp.GetEmailVerified() {
		t.Fatal("expected email_verified true")
	}
}

func TestAuthHandler_GetUserAuthInfo_InvalidUserID(t *testing.T) {
	h := newTestHandler(&mockAuthService{})

	resp, err := h.GetUserAuthInfo(context.Background(), &authv1.GetUserAuthInfoRequest{
		UserId: "bad-user-id",
	})

	if resp != nil {
		t.Fatal("expected nil response")
	}

	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestAuthHandler_GetJWKS_Success(t *testing.T) {
	mock := &mockAuthService{
		getJWKSFunc: func(ctx context.Context) (string, error) {
			return `{"keys":[]}`, nil
		},
	}

	h := newTestHandler(mock)

	resp, err := h.GetJWKS(context.Background(), &authv1.GetJWKSRequest{})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if resp.GetJwksJson() != `{"keys":[]}` {
		t.Fatalf("expected jwks json, got %s", resp.GetJwksJson())
	}
}

func TestAuthHandler_GetJWKS_ServiceError(t *testing.T) {
	mock := &mockAuthService{
		getJWKSFunc: func(ctx context.Context) (string, error) {
			return "", errors.New("jwks error")
		},
	}

	h := newTestHandler(mock)

	resp, err := h.GetJWKS(context.Background(), &authv1.GetJWKSRequest{})

	if resp != nil {
		t.Fatal("expected nil response")
	}

	assertGRPCCode(t, err, codes.Internal)
}

func TestAuthHandler_ChangePassword_Success(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	mock := &mockAuthService{
		changePasswordFunc: func(ctx context.Context, in models.ChangePasswordInput) (*models.ChangePasswordResult, error) {
			if in.UserID != userID {
				t.Fatalf("expected user_id %s, got %s", userID.String(), in.UserID.String())
			}

			if in.SessionID != sessionID {
				t.Fatalf("expected session_id %s, got %s", sessionID.String(), in.SessionID.String())
			}

			if in.OldPassword != "old-password" {
				t.Fatalf("expected old-password, got %s", in.OldPassword)
			}

			if in.NewPassword != "new-password" {
				t.Fatalf("expected new-password, got %s", in.NewPassword)
			}

			if !in.RevokeOtherSessions {
				t.Fatal("expected revoke_other_sessions true")
			}

			return &models.ChangePasswordResult{
				Success:                  true,
				InvalidatedSessionsCount: 2,
			}, nil
		},
	}

	h := newTestHandler(mock)

	resp, err := h.ChangePassword(context.Background(), &authv1.ChangePasswordRequest{
		UserId:              userID.String(),
		SessionId:           sessionID.String(),
		OldPassword:         "old-password",
		NewPassword:         "new-password",
		RevokeOtherSessions: true,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !resp.GetSuccess() {
		t.Fatal("expected success true")
	}

	if resp.GetInvalidatedSessionsCount() != 2 {
		t.Fatalf("expected invalidated_sessions_count 2, got %d", resp.GetInvalidatedSessionsCount())
	}
}

func TestAuthHandler_ChangePassword_InvalidUserID(t *testing.T) {
	h := newTestHandler(&mockAuthService{})

	resp, err := h.ChangePassword(context.Background(), &authv1.ChangePasswordRequest{
		UserId:    "bad-user-id",
		SessionId: uuid.New().String(),
	})

	if resp != nil {
		t.Fatal("expected nil response")
	}

	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestAuthHandler_ChangePassword_InvalidSessionID(t *testing.T) {
	h := newTestHandler(&mockAuthService{})

	resp, err := h.ChangePassword(context.Background(), &authv1.ChangePasswordRequest{
		UserId:    uuid.New().String(),
		SessionId: "bad-session-id",
	})

	if resp != nil {
		t.Fatal("expected nil response")
	}

	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestAuthHandler_SendVerificationEmail_Success(t *testing.T) {
	userID := uuid.New()

	mock := &mockAuthService{
		sendVerificationFunc: func(ctx context.Context, in models.SendVerificationEmailInput) (*models.SendVerificationEmailResult, error) {
			if in.UserID != userID {
				t.Fatalf("expected user_id %s, got %s", userID.String(), in.UserID.String())
			}

			if in.Email != "test@example.com" {
				t.Fatalf("expected email test@example.com, got %s", in.Email)
			}

			return &models.SendVerificationEmailResult{
				Success:       true,
				ExpiresAtUnix: 100,
			}, nil
		},
	}

	h := newTestHandler(mock)

	resp, err := h.SendVerificationEmail(context.Background(), &authv1.SendVerificationEmailRequest{
		UserId: userID.String(),
		Email:  "test@example.com",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !resp.GetSuccess() {
		t.Fatal("expected success true")
	}

	if resp.GetExpiresAtUnix() != 100 {
		t.Fatalf("expected expires_at_unix 100, got %d", resp.GetExpiresAtUnix())
	}
}

func TestAuthHandler_SendVerificationEmail_InvalidUserID(t *testing.T) {
	h := newTestHandler(&mockAuthService{})

	resp, err := h.SendVerificationEmail(context.Background(), &authv1.SendVerificationEmailRequest{
		UserId: "bad-user-id",
		Email:  "test@example.com",
	})

	if resp != nil {
		t.Fatal("expected nil response")
	}

	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestAuthHandler_VerifyEmail_Success(t *testing.T) {
	userID := uuid.New()

	mock := &mockAuthService{
		verifyEmailFunc: func(ctx context.Context, in models.VerifyEmailInput) (*models.VerifyEmailResult, error) {
			if in.Token != "verify-token" {
				t.Fatalf("expected verify-token, got %s", in.Token)
			}

			return &models.VerifyEmailResult{
				Success:       true,
				UserID:        userID,
				Email:         "test@example.com",
				EmailVerified: true,
				Message:       "email verified",
			}, nil
		},
	}

	h := newTestHandler(mock)

	resp, err := h.VerifyEmail(context.Background(), &authv1.VerifyEmailRequest{
		Token: "verify-token",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !resp.GetSuccess() {
		t.Fatal("expected success true")
	}

	if resp.GetUserId() != userID.String() {
		t.Fatalf("expected user_id %s, got %s", userID.String(), resp.GetUserId())
	}

	if resp.GetEmail() != "test@example.com" {
		t.Fatalf("expected email test@example.com, got %s", resp.GetEmail())
	}

	if !resp.GetEmailVerified() {
		t.Fatal("expected email_verified true")
	}

	if resp.GetMessage() != "email verified" {
		t.Fatalf("expected message email verified, got %s", resp.GetMessage())
	}
}

func TestAuthHandler_RequestPasswordReset_Success(t *testing.T) {
	mock := &mockAuthService{
		requestPasswordResetFunc: func(ctx context.Context, in models.RequestPasswordResetInput) (*models.RequestPasswordResetResult, error) {
			if in.Email != "test@example.com" {
				t.Fatalf("expected email test@example.com, got %s", in.Email)
			}

			return &models.RequestPasswordResetResult{
				Success:       true,
				ExpiresAtUnix: 200,
			}, nil
		},
	}

	h := newTestHandler(mock)

	resp, err := h.RequestPasswordReset(context.Background(), &authv1.RequestPasswordResetRequest{
		Email: "test@example.com",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !resp.GetSuccess() {
		t.Fatal("expected success true")
	}

	if resp.GetExpiresAtUnix() != 200 {
		t.Fatalf("expected expires_at_unix 200, got %d", resp.GetExpiresAtUnix())
	}
}

func TestAuthHandler_ResetPassword_Success(t *testing.T) {
	mock := &mockAuthService{
		resetPasswordFunc: func(ctx context.Context, in models.ResetPasswordInput) (*models.ResetPasswordResult, error) {
			if in.Token != "reset-token" {
				t.Fatalf("expected reset-token, got %s", in.Token)
			}

			if in.NewPassword != "new-password" {
				t.Fatalf("expected new-password, got %s", in.NewPassword)
			}

			return &models.ResetPasswordResult{
				Success:                  true,
				InvalidatedSessionsCount: 4,
			}, nil
		},
	}

	h := newTestHandler(mock)

	resp, err := h.ResetPassword(context.Background(), &authv1.ResetPasswordRequest{
		Token:       "reset-token",
		NewPassword: "new-password",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !resp.GetSuccess() {
		t.Fatal("expected success true")
	}

	if resp.GetInvalidatedSessionsCount() != 4 {
		t.Fatalf("expected invalidated_sessions_count 4, got %d", resp.GetInvalidatedSessionsCount())
	}
}
