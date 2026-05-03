package models

import (
	"testing"

	"github.com/google/uuid"
)

func TestRegisterInputValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   RegisterInput
		wantErr bool
	}{
		{
			name: "valid input",
			input: RegisterInput{
				Email:    "test@example.com",
				Password: "password123",
				Username: "testuser",
			},
			wantErr: false,
		},
		{
			name: "empty email",
			input: RegisterInput{
				Email:    "",
				Password: "password123",
				Username: "testuser",
			},
			wantErr: true,
		},
		{
			name: "invalid email",
			input: RegisterInput{
				Email:    "bad-email",
				Password: "password123",
				Username: "testuser",
			},
			wantErr: true,
		},
		{
			name: "empty password",
			input: RegisterInput{
				Email:    "test@example.com",
				Password: "",
				Username: "testuser",
			},
			wantErr: true,
		},
		{
			name: "short password",
			input: RegisterInput{
				Email:    "test@example.com",
				Password: "123",
				Username: "testuser",
			},
			wantErr: true,
		},
		{
			name: "empty username",
			input: RegisterInput{
				Email:    "test@example.com",
				Password: "password123",
				Username: "",
			},
			wantErr: true,
		},
		{
			name: "spaces only username",
			input: RegisterInput{
				Email:    "test@example.com",
				Password: "password123",
				Username: "   ",
			},
			wantErr: true,
		},
		{
			name: "all fields empty",
			input: RegisterInput{
				Email:    "",
				Password: "",
				Username: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestLoginInputValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   LoginInput
		wantErr bool
	}{
		{
			name: "valid input",
			input: LoginInput{
				Email:     "test@example.com",
				Password:  "password123",
				ClientID:  "web-client",
				IP:        "127.0.0.1",
				UserAgent: "Mozilla/5.0",
			},
			wantErr: false,
		},
		{
			name: "empty email",
			input: LoginInput{
				Email:     "",
				Password:  "password123",
				ClientID:  "web-client",
				IP:        "127.0.0.1",
				UserAgent: "Mozilla/5.0",
			},
			wantErr: true,
		},
		{
			name: "invalid email",
			input: LoginInput{
				Email:     "bad-email",
				Password:  "password123",
				ClientID:  "web-client",
				IP:        "127.0.0.1",
				UserAgent: "Mozilla/5.0",
			},
			wantErr: true,
		},
		{
			name: "empty password",
			input: LoginInput{
				Email:     "test@example.com",
				Password:  "",
				ClientID:  "web-client",
				IP:        "127.0.0.1",
				UserAgent: "Mozilla/5.0",
			},
			wantErr: true,
		},
		{
			name: "empty client id",
			input: LoginInput{
				Email:     "test@example.com",
				Password:  "password123",
				ClientID:  "",
				IP:        "127.0.0.1",
				UserAgent: "Mozilla/5.0",
			},
			wantErr: true,
		},
		{
			name: "empty ip",
			input: LoginInput{
				Email:     "test@example.com",
				Password:  "password123",
				ClientID:  "web-client",
				IP:        "",
				UserAgent: "Mozilla/5.0",
			},
			wantErr: true,
		},
		{
			name: "empty user agent",
			input: LoginInput{
				Email:     "test@example.com",
				Password:  "password123",
				ClientID:  "web-client",
				IP:        "127.0.0.1",
				UserAgent: "",
			},
			wantErr: true,
		},
		{
			name: "all fields empty",
			input: LoginInput{
				Email:     "",
				Password:  "",
				ClientID:  "",
				IP:        "",
				UserAgent: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestRefreshInputValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   RefreshInput
		wantErr bool
	}{
		{
			name: "valid input",
			input: RefreshInput{
				RefreshToken: "refresh-token",
				ClientID:     "web-client",
				IP:           "127.0.0.1",
				UserAgent:    "Mozilla/5.0",
			},
			wantErr: false,
		},
		{
			name: "empty refresh token",
			input: RefreshInput{
				RefreshToken: "",
				ClientID:     "web-client",
				IP:           "127.0.0.1",
				UserAgent:    "Mozilla/5.0",
			},
			wantErr: true,
		},
		{
			name: "empty client id",
			input: RefreshInput{
				RefreshToken: "refresh-token",
				ClientID:     "",
				IP:           "127.0.0.1",
				UserAgent:    "Mozilla/5.0",
			},
			wantErr: true,
		},
		{
			name: "empty ip",
			input: RefreshInput{
				RefreshToken: "refresh-token",
				ClientID:     "web-client",
				IP:           "",
				UserAgent:    "Mozilla/5.0",
			},
			wantErr: true,
		},
		{
			name: "empty user agent",
			input: RefreshInput{
				RefreshToken: "refresh-token",
				ClientID:     "web-client",
				IP:           "127.0.0.1",
				UserAgent:    "",
			},
			wantErr: true,
		},
		{
			name: "all fields empty",
			input: RefreshInput{
				RefreshToken: "",
				ClientID:     "",
				IP:           "",
				UserAgent:    "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestLogoutInputValidate(t *testing.T) {
	validUserID := uuid.New()
	validSessionID := uuid.New()

	tests := []struct {
		name    string
		input   LogoutInput
		wantErr bool
	}{
		{
			name: "valid input",
			input: LogoutInput{
				UserID:    validUserID,
				SessionID: validSessionID,
			},
			wantErr: false,
		},
		{
			name: "empty user id",
			input: LogoutInput{
				UserID:    uuid.Nil,
				SessionID: validSessionID,
			},
			wantErr: true,
		},
		{
			name: "empty session id",
			input: LogoutInput{
				UserID:    validUserID,
				SessionID: uuid.Nil,
			},
			wantErr: true,
		},
		{
			name: "all ids empty",
			input: LogoutInput{
				UserID:    uuid.Nil,
				SessionID: uuid.Nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestLogoutAllInputValidate(t *testing.T) {
	validUserID := uuid.New()

	tests := []struct {
		name    string
		input   LogoutAllInput
		wantErr bool
	}{
		{
			name: "valid input",
			input: LogoutAllInput{
				UserID: validUserID,
			},
			wantErr: false,
		},
		{
			name: "empty user id",
			input: LogoutAllInput{
				UserID: uuid.Nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestChangePasswordInputValidate(t *testing.T) {
	validUserID := uuid.New()
	validSessionID := uuid.New()

	tests := []struct {
		name    string
		input   ChangePasswordInput
		wantErr bool
	}{
		{
			name: "valid input without revoke other sessions",
			input: ChangePasswordInput{
				UserID:              validUserID,
				OldPassword:         "old-password",
				NewPassword:         "new-password-123",
				SessionID:           validSessionID,
				RevokeOtherSessions: false,
			},
			wantErr: false,
		},
		{
			name: "valid input with revoke other sessions",
			input: ChangePasswordInput{
				UserID:              validUserID,
				OldPassword:         "old-password",
				NewPassword:         "new-password-123",
				SessionID:           validSessionID,
				RevokeOtherSessions: true,
			},
			wantErr: false,
		},
		{
			name: "empty user id",
			input: ChangePasswordInput{
				UserID:      uuid.Nil,
				OldPassword: "old-password",
				NewPassword: "new-password-123",
				SessionID:   validSessionID,
			},
			wantErr: true,
		},
		{
			name: "empty session id",
			input: ChangePasswordInput{
				UserID:      validUserID,
				OldPassword: "old-password",
				NewPassword: "new-password-123",
				SessionID:   uuid.Nil,
			},
			wantErr: true,
		},
		{
			name: "empty old password",
			input: ChangePasswordInput{
				UserID:      validUserID,
				OldPassword: "",
				NewPassword: "new-password-123",
				SessionID:   validSessionID,
			},
			wantErr: true,
		},
		{
			name: "empty new password",
			input: ChangePasswordInput{
				UserID:      validUserID,
				OldPassword: "old-password",
				NewPassword: "",
				SessionID:   validSessionID,
			},
			wantErr: true,
		},
		{
			name: "short new password",
			input: ChangePasswordInput{
				UserID:      validUserID,
				OldPassword: "old-password",
				NewPassword: "123",
				SessionID:   validSessionID,
			},
			wantErr: true,
		},
		{
			name: "same old and new password",
			input: ChangePasswordInput{
				UserID:      validUserID,
				OldPassword: "same-password",
				NewPassword: "same-password",
				SessionID:   validSessionID,
			},
			wantErr: true,
		},
		{
			name: "all fields empty",
			input: ChangePasswordInput{
				UserID:      uuid.Nil,
				OldPassword: "",
				NewPassword: "",
				SessionID:   uuid.Nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestSendVerificationEmailInputValidate(t *testing.T) {
	validUserID := uuid.New()

	tests := []struct {
		name    string
		input   SendVerificationEmailInput
		wantErr bool
	}{
		{
			name: "valid input with email",
			input: SendVerificationEmailInput{
				UserID: validUserID,
				Email:  "test@example.com",
			},
			wantErr: false,
		},
		{
			name: "valid input without email",
			input: SendVerificationEmailInput{
				UserID: validUserID,
				Email:  "",
			},
			wantErr: false,
		},
		{
			name: "valid input with email spaces",
			input: SendVerificationEmailInput{
				UserID: validUserID,
				Email:  "   ",
			},
			wantErr: false,
		},
		{
			name: "invalid email",
			input: SendVerificationEmailInput{
				UserID: validUserID,
				Email:  "bad-email",
			},
			wantErr: true,
		},
		{
			name: "empty user id",
			input: SendVerificationEmailInput{
				UserID: uuid.Nil,
				Email:  "test@example.com",
			},
			wantErr: true,
		},
		{
			name: "empty user id and empty email",
			input: SendVerificationEmailInput{
				UserID: uuid.Nil,
				Email:  "",
			},
			wantErr: true,
		},
		{
			name: "empty user id and invalid email",
			input: SendVerificationEmailInput{
				UserID: uuid.Nil,
				Email:  "bad-email",
			},
			wantErr: true,
		},
		{
			name: "email should be normalized",
			input: SendVerificationEmailInput{
				UserID: validUserID,
				Email:  "  TEST@EXAMPLE.COM  ",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestVerifyEmailInputValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   VerifyEmailInput
		wantErr bool
	}{
		{
			name: "valid input",
			input: VerifyEmailInput{
				Token: "email-verification-token",
			},
			wantErr: false,
		},
		{
			name: "empty token",
			input: VerifyEmailInput{
				Token: "",
			},
			wantErr: true,
		},
		{
			name: "spaces only token",
			input: VerifyEmailInput{
				Token: "   ",
			},
			wantErr: true,
		},
		{
			name: "short token is allowed by validation",
			input: VerifyEmailInput{
				Token: "abc",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestRequestPasswordResetInputValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   RequestPasswordResetInput
		wantErr bool
	}{
		{
			name: "valid input",
			input: RequestPasswordResetInput{
				Email: "test@example.com",
			},
			wantErr: false,
		},
		{
			name: "empty email",
			input: RequestPasswordResetInput{
				Email: "",
			},
			wantErr: true,
		},
		{
			name: "invalid email",
			input: RequestPasswordResetInput{
				Email: "bad-email",
			},
			wantErr: true,
		},
		{
			name: "spaces only email",
			input: RequestPasswordResetInput{
				Email: "   ",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestResetPasswordInputValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   ResetPasswordInput
		wantErr bool
	}{
		{
			name: "valid input",
			input: ResetPasswordInput{
				Token:       "reset-token",
				NewPassword: "new-password-123",
			},
			wantErr: false,
		},
		{
			name: "empty token",
			input: ResetPasswordInput{
				Token:       "",
				NewPassword: "new-password-123",
			},
			wantErr: true,
		},
		{
			name: "spaces only token",
			input: ResetPasswordInput{
				Token:       "   ",
				NewPassword: "new-password-123",
			},
			wantErr: true,
		},
		{
			name: "short token is allowed by validation",
			input: ResetPasswordInput{
				Token:       "abc",
				NewPassword: "new-password-123",
			},
			wantErr: false,
		},
		{
			name: "empty new password",
			input: ResetPasswordInput{
				Token:       "reset-token",
				NewPassword: "",
			},
			wantErr: true,
		},
		{
			name: "short new password",
			input: ResetPasswordInput{
				Token:       "reset-token",
				NewPassword: "123",
			},
			wantErr: true,
		},
		{
			name: "all fields empty",
			input: ResetPasswordInput{
				Token:       "",
				NewPassword: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestSendVerificationEmailInputValidate_NormalizesEmail(t *testing.T) {
	in := SendVerificationEmailInput{
		UserID: uuid.New(),
		Email:  "  TEST@EXAMPLE.COM  ",
	}

	err := in.Validate()
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if in.Email != "test@example.com" {
		t.Fatalf("expected normalized email %q, got %q", "test@example.com", in.Email)
	}
}
