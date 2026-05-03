package integration

import (
	"auth/models"
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestAuthServiceIntegration_RegisterLoginRefreshLogout(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()

	email := uniqueEmail()
	password := "Password123!"

	registerResult, err := app.auth.Register(ctx, models.RegisterInput{
		Email:    email,
		Username: "integration_user",
		Password: password,
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	if registerResult.UserID == "" {
		t.Fatal("expected user id")
	}

	if registerResult.Email != email {
		t.Fatalf("expected email %s, got %s", email, registerResult.Email)
	}

	userID, err := uuid.Parse(registerResult.UserID)
	if err != nil {
		t.Fatalf("failed to parse user id: %v", err)
	}

	loginResult, err := app.auth.Login(ctx, models.LoginInput{
		Email:     email,
		Password:  password,
		ClientID:  "web-client",
		IP:        "127.0.0.1",
		UserAgent: "integration-test",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if loginResult.AccessToken == "" {
		t.Fatal("expected access token")
	}

	if loginResult.RefreshToken == "" {
		t.Fatal("expected refresh token")
	}

	if loginResult.SessionID == uuid.Nil {
		t.Fatal("expected session id")
	}

	sessionID := loginResult.SessionID

	refreshResult, err := app.auth.Refresh(ctx, models.RefreshInput{
		RefreshToken: loginResult.RefreshToken,
		ClientID:     "web-client",
		IP:           "127.0.0.1",
		UserAgent:    "integration-test",
	})
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	if refreshResult.AccessToken == "" {
		t.Fatal("expected refreshed access token")
	}

	if refreshResult.RefreshToken == "" {
		t.Fatal("expected refreshed refresh token")
	}

	authInfo, err := app.auth.GetUserAuthInfo(ctx, userID)
	if err != nil {
		t.Fatalf("get user auth info failed: %v", err)
	}

	if authInfo.UserID != userID {
		t.Fatalf("expected user id %s, got %s", userID, authInfo.UserID)
	}

	if authInfo.Email != email {
		t.Fatalf("expected email %s, got %s", email, authInfo.Email)
	}

	if !authInfo.IsActive {
		t.Fatal("expected user active")
	}

	err = app.auth.Logout(ctx, models.LogoutInput{
		UserID:    userID,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatalf("logout failed: %v", err)
	}

	_, err = app.auth.Refresh(ctx, models.RefreshInput{
		RefreshToken: refreshResult.RefreshToken,
		ClientID:     "web-client",
		IP:           "127.0.0.1",
		UserAgent:    "integration-test",
	})
	if err == nil {
		t.Fatal("expected refresh to fail after logout")
	}
}

func TestAuthServiceIntegration_RegisterDuplicateEmailFails(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()

	email := uniqueEmail()

	_, err := app.auth.Register(ctx, models.RegisterInput{
		Email:    email,
		Username: "first_user",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("first register failed: %v", err)
	}

	_, err = app.auth.Register(ctx, models.RegisterInput{
		Email:    email,
		Username: "second_user",
		Password: "Password123!",
	})
	if err == nil {
		t.Fatal("expected duplicate email register to fail")
	}
}

func TestAuthServiceIntegration_SendVerificationAndVerifyEmail(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()

	email := uniqueEmail()

	registerResult, err := app.auth.Register(ctx, models.RegisterInput{
		Email:    email,
		Username: "verify_user",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	userID, err := uuid.Parse(registerResult.UserID)
	if err != nil {
		t.Fatalf("failed to parse user id: %v", err)
	}

	_, err = app.auth.SendVerification(ctx, models.SendVerificationEmailInput{
		UserID: userID,
		Email:  email,
	})
	if err != nil {
		t.Fatalf("send verification failed: %v", err)
	}

	token := app.mail.getVerificationToken()
	if token == "" {
		t.Fatal("expected verification token to be sent")
	}

	verifyResult, err := app.auth.VerifyEmail(ctx, models.VerifyEmailInput{
		Token: token,
	})
	if err != nil {
		t.Fatalf("verify email failed: %v", err)
	}

	if !verifyResult.Success {
		t.Fatal("expected verify success")
	}

	authInfo, err := app.auth.GetUserAuthInfo(ctx, userID)
	if err != nil {
		t.Fatalf("get user auth info failed: %v", err)
	}

	if !authInfo.EmailVerified {
		t.Fatal("expected email_verified true")
	}
}

func TestAuthServiceIntegration_ChangePassword(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()

	email := uniqueEmail()
	oldPassword := "Password123!"
	newPassword := "NewPassword123!"

	registerResult, err := app.auth.Register(ctx, models.RegisterInput{
		Email:    email,
		Username: "change_password_user",
		Password: oldPassword,
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	userID, err := uuid.Parse(registerResult.UserID)
	if err != nil {
		t.Fatalf("failed to parse user id: %v", err)
	}

	loginResult, err := app.auth.Login(ctx, models.LoginInput{
		Email:     email,
		Password:  oldPassword,
		ClientID:  "web-client",
		IP:        "127.0.0.1",
		UserAgent: "integration-test",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	sessionID := loginResult.SessionID

	_, err = app.auth.ChangePassword(ctx, models.ChangePasswordInput{
		UserID:              userID,
		SessionID:           sessionID,
		OldPassword:         oldPassword,
		NewPassword:         newPassword,
		RevokeOtherSessions: false,
	})
	if err != nil {
		t.Fatalf("change password failed: %v", err)
	}

	_, err = app.auth.Login(ctx, models.LoginInput{
		Email:     email,
		Password:  oldPassword,
		ClientID:  "web-client",
		IP:        "127.0.0.1",
		UserAgent: "integration-test",
	})
	if err == nil {
		t.Fatal("expected login with old password to fail")
	}

	_, err = app.auth.Login(ctx, models.LoginInput{
		Email:     email,
		Password:  newPassword,
		ClientID:  "web-client",
		IP:        "127.0.0.1",
		UserAgent: "integration-test",
	})
	if err != nil {
		t.Fatalf("expected login with new password to succeed, got %v", err)
	}
}

func TestAuthServiceIntegration_RequestAndResetPassword(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()

	email := uniqueEmail()
	oldPassword := "Password123!"
	newPassword := "ResetPassword123!"

	_, err := app.auth.Register(ctx, models.RegisterInput{
		Email:    email,
		Username: "reset_password_user",
		Password: oldPassword,
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	_, err = app.auth.RequestPasswordReset(ctx, models.RequestPasswordResetInput{
		Email: email,
	})
	if err != nil {
		t.Fatalf("request password reset failed: %v", err)
	}

	token := app.mail.getPasswordResetToken()
	if token == "" {
		t.Fatal("expected password reset token to be sent")
	}

	resetResult, err := app.auth.ResetPassword(ctx, models.ResetPasswordInput{
		Token:       token,
		NewPassword: newPassword,
	})
	if err != nil {
		t.Fatalf("reset password failed: %v", err)
	}

	if !resetResult.Success {
		t.Fatal("expected reset password success")
	}

	_, err = app.auth.Login(ctx, models.LoginInput{
		Email:     email,
		Password:  oldPassword,
		ClientID:  "web-client",
		IP:        "127.0.0.1",
		UserAgent: "integration-test",
	})
	if err == nil {
		t.Fatal("expected login with old password to fail")
	}

	_, err = app.auth.Login(ctx, models.LoginInput{
		Email:     email,
		Password:  newPassword,
		ClientID:  "web-client",
		IP:        "127.0.0.1",
		UserAgent: "integration-test",
	})
	if err != nil {
		t.Fatalf("expected login with new password to succeed, got %v", err)
	}
}

func TestAuthServiceIntegration_GetJWKS(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()

	jwks, err := app.auth.GetJWKS(ctx)
	if err != nil {
		t.Fatalf("get jwks failed: %v", err)
	}

	if jwks == "" {
		t.Fatal("expected jwks not empty")
	}
}
