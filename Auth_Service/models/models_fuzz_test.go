package models

import (
	"testing"

	"github.com/google/uuid"
)

func FuzzRegisterInputValidate(f *testing.F) {
	f.Add("test@example.com", "password123", "testuser")
	f.Add("", "", "")
	f.Add("bad-email", "123", "a")
	f.Add("admin@site.com", "very-long-password", "admin")
	f.Add("тест@example.com", "пароль123", "Иван")

	f.Fuzz(func(t *testing.T, email string, password string, username string) {
		in := RegisterInput{
			Email:    email,
			Password: password,
			Username: username,
		}

		err := in.Validate()

		if email == "" && err == nil {
			t.Fatal("empty email should be invalid")
		}

		if password == "" && err == nil {
			t.Fatal("empty password should be invalid")
		}

		if username == "" && err == nil {
			t.Fatal("empty username should be invalid")
		}
	})
}

func FuzzLoginInputValidate(f *testing.F) {
	f.Add("test@example.com", "password123", "web", "127.0.0.1", "Mozilla/5.0")
	f.Add("", "", "", "", "")
	f.Add("bad-email", "123", "client", "bad-ip", "")
	f.Add("admin@site.com", "password", "mobile", "::1", "test-agent")

	f.Fuzz(func(t *testing.T, email string, password string, clientID string, ip string, userAgent string) {
		in := LoginInput{
			Email:     email,
			Password:  password,
			ClientID:  clientID,
			IP:        ip,
			UserAgent: userAgent,
		}

		err := in.Validate()

		if email == "" && err == nil {
			t.Fatal("empty email should be invalid")
		}

		if password == "" && err == nil {
			t.Fatal("empty password should be invalid")
		}

		if clientID == "" && err == nil {
			t.Fatal("empty client_id should be invalid")
		}
	})
}

func FuzzRefreshInputValidate(f *testing.F) {
	f.Add("refresh-token", "web", "127.0.0.1", "Mozilla/5.0")
	f.Add("", "", "", "")
	f.Add("%%%bad-token%%%", "client", "bad-ip", "")
	f.Add("очень-странный-токен", "mobile", "::1", "agent")

	f.Fuzz(func(t *testing.T, refreshToken string, clientID string, ip string, userAgent string) {
		in := RefreshInput{
			RefreshToken: refreshToken,
			ClientID:     clientID,
			IP:           ip,
			UserAgent:    userAgent,
		}

		err := in.Validate()

		if refreshToken == "" && err == nil {
			t.Fatal("empty refresh token should be invalid")
		}

		if clientID == "" && err == nil {
			t.Fatal("empty client_id should be invalid")
		}
	})
}

func FuzzVerifyEmailInputValidate(f *testing.F) {
	f.Add("email-verification-token")
	f.Add("")
	f.Add("%%%bad-token%%%")
	f.Add("токен-на-русском")
	f.Add("\x00\x01\x02")

	f.Fuzz(func(t *testing.T, token string) {
		in := VerifyEmailInput{
			Token: token,
		}

		err := in.Validate()

		if token == "" && err == nil {
			t.Fatal("empty token should be invalid")
		}
	})
}

func FuzzRequestPasswordResetInputValidate(f *testing.F) {
	f.Add("test@example.com")
	f.Add("")
	f.Add("bad-email")
	f.Add("admin@site.com")
	f.Add("тест@example.com")

	f.Fuzz(func(t *testing.T, email string) {
		in := RequestPasswordResetInput{
			Email: email,
		}

		err := in.Validate()

		if email == "" && err == nil {
			t.Fatal("empty email should be invalid")
		}
	})
}

func FuzzResetPasswordInputValidate(f *testing.F) {
	f.Add("reset-token", "new-password-123")
	f.Add("", "")
	f.Add("%%%bad-token%%%", "123")
	f.Add("токен", "пароль123")
	f.Add("\x00\x01\x02", "\x00\x01\x02")

	f.Fuzz(func(t *testing.T, token string, newPassword string) {
		in := ResetPasswordInput{
			Token:       token,
			NewPassword: newPassword,
		}

		err := in.Validate()

		if token == "" && err == nil {
			t.Fatal("empty token should be invalid")
		}

		if newPassword == "" && err == nil {
			t.Fatal("empty new password should be invalid")
		}
	})
}

func FuzzLogoutInputValidate(f *testing.F) {
	validUserID := uuid.New().String()
	validSessionID := uuid.New().String()

	f.Add(validUserID, validSessionID)
	f.Add("", "")
	f.Add("bad-user-id", "bad-session-id")
	f.Add(uuid.Nil.String(), uuid.Nil.String())

	f.Fuzz(func(t *testing.T, userIDRaw string, sessionIDRaw string) {
		userID, _ := uuid.Parse(userIDRaw)
		sessionID, _ := uuid.Parse(sessionIDRaw)

		in := LogoutInput{
			UserID:    userID,
			SessionID: sessionID,
		}

		err := in.Validate()

		if userID == uuid.Nil && err == nil {
			t.Fatal("empty user_id should be invalid")
		}

		if sessionID == uuid.Nil && err == nil {
			t.Fatal("empty session_id should be invalid")
		}
	})
}

func FuzzLogoutAllInputValidate(f *testing.F) {
	validUserID := uuid.New().String()

	f.Add(validUserID)
	f.Add("")
	f.Add("bad-user-id")
	f.Add(uuid.Nil.String())

	f.Fuzz(func(t *testing.T, userIDRaw string) {
		userID, _ := uuid.Parse(userIDRaw)

		in := LogoutAllInput{
			UserID: userID,
		}

		err := in.Validate()

		if userID == uuid.Nil && err == nil {
			t.Fatal("empty user_id should be invalid")
		}
	})
}

func FuzzChangePasswordInputValidate(f *testing.F) {
	validUserID := uuid.New().String()
	validSessionID := uuid.New().String()

	f.Add(validUserID, validSessionID, "old-password", "new-password-123", true)
	f.Add("", "", "", "", false)
	f.Add("bad-user-id", "bad-session-id", "old", "new", true)
	f.Add(uuid.Nil.String(), uuid.Nil.String(), "old-password", "new-password", false)

	f.Fuzz(func(t *testing.T, userIDRaw string, sessionIDRaw string, oldPassword string, newPassword string, revokeOtherSessions bool) {
		userID, _ := uuid.Parse(userIDRaw)
		sessionID, _ := uuid.Parse(sessionIDRaw)

		in := ChangePasswordInput{
			UserID:              userID,
			SessionID:           sessionID,
			OldPassword:         oldPassword,
			NewPassword:         newPassword,
			RevokeOtherSessions: revokeOtherSessions,
		}

		err := in.Validate()

		if userID == uuid.Nil && err == nil {
			t.Fatal("empty user_id should be invalid")
		}

		if sessionID == uuid.Nil && err == nil {
			t.Fatal("empty session_id should be invalid")
		}

		if oldPassword == "" && err == nil {
			t.Fatal("empty old password should be invalid")
		}

		if newPassword == "" && err == nil {
			t.Fatal("empty new password should be invalid")
		}
	})
}

func FuzzSendVerificationEmailInputValidate(f *testing.F) {
	validUserID := uuid.New().String()

	f.Add(validUserID, "test@example.com")
	f.Add("", "")
	f.Add("bad-user-id", "bad-email")
	f.Add(uuid.Nil.String(), "test@example.com")

	f.Fuzz(func(t *testing.T, userIDRaw string, email string) {
		userID, _ := uuid.Parse(userIDRaw)

		in := SendVerificationEmailInput{
			UserID: userID,
			Email:  email,
		}

		err := in.Validate()

		if userID == uuid.Nil && err == nil {
			t.Fatal("empty user_id should be invalid")
		}

		if email == "" && err == nil {
			t.Fatal("empty email should be invalid")
		}
	})
}
