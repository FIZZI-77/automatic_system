package models

import (
	"time"

	"github.com/google/uuid"
)

// TokenType задаёт тип доменной модели.
type TokenType string

const (
	TokenTypeEmailVerification TokenType = "email_verification"
	TokenTypePasswordReset     TokenType = "password_reset"
)

// OneTimeToken описывает одноразовый токен и срок его действия.
type OneTimeToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	Type      TokenType
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// RegisterInput задаёт входные данные операции.
type RegisterInput struct {
	Email    string
	Password string
	Username string
}

// RegisterResult содержит результат операции.
type RegisterResult struct {
	UserID        string
	Email         string
	EmailVerified bool
}

// LoginInput задаёт входные данные операции.
type LoginInput struct {
	Email     string
	Password  string
	ClientID  string
	IP        string
	UserAgent string
}

// LoginResult содержит результат операции.
type LoginResult struct {
	AccessToken          string
	RefreshToken         string
	AccessExpiresAtUnix  int64
	RefreshExpiresAtUnix int64
	SessionID            uuid.UUID
	TokenType            string
}

// RefreshInput задаёт входные данные операции.
type RefreshInput struct {
	RefreshToken string
	ClientID     string
	IP           string
	UserAgent    string
}

// RefreshResult содержит результат операции.
type RefreshResult struct {
	AccessToken          string
	RefreshToken         string
	AccessExpiresAtUnix  int64
	RefreshExpiresAtUnix int64
	SessionID            uuid.UUID
	TokenType            string
}

// LogoutInput задаёт входные данные операции.
type LogoutInput struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
}

// LogoutAllInput задаёт входные данные операции.
type LogoutAllInput struct {
	UserID uuid.UUID
}

// UserAuthInfo описывает доменную модель.
type UserAuthInfo struct {
	UserID        uuid.UUID
	Email         string
	Roles         []string
	Permissions   []string
	IsActive      bool
	EmailVerified bool
}

// User описывает доменную модель.
type User struct {
	ID            uuid.UUID
	Email         string
	Username      string
	PasswordHash  string
	IsActive      bool
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Session описывает доменную модель.
type Session struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	ClientID   string
	IP         string
	UserAgent  string
	IsRevoked  bool
	RevokedAt  *time.Time
	ExpiresAt  time.Time
	LastSeenAt *time.Time
	CreatedAt  time.Time
}

// RefreshToken описывает доменную модель.
type RefreshToken struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	SessionID         uuid.UUID
	TokenHash         string
	IsRevoked         bool
	RevokedAt         *time.Time
	ExpiresAt         time.Time
	UsedAt            *time.Time
	ReplacedByTokenID *string
	CreatedAt         time.Time
}

// ChangePasswordInput задаёт входные данные операции.
type ChangePasswordInput struct {
	UserID              uuid.UUID
	OldPassword         string
	NewPassword         string
	SessionID           uuid.UUID
	RevokeOtherSessions bool
}

// ChangePasswordResult содержит результат операции.
type ChangePasswordResult struct {
	Success                  bool
	InvalidatedSessionsCount int32
}

// SendVerificationEmailInput задаёт входные данные операции.
type SendVerificationEmailInput struct {
	UserID uuid.UUID
	Email  string
}

// SendVerificationEmailResult содержит результат операции.
type SendVerificationEmailResult struct {
	Success       bool
	ExpiresAtUnix int64
}

// VerifyEmailInput задаёт входные данные операции.
type VerifyEmailInput struct {
	Token string
}

// VerifyEmailResult содержит результат операции.
type VerifyEmailResult struct {
	Success       bool
	UserID        uuid.UUID
	Email         string
	EmailVerified bool
	Message       string
}

// RequestPasswordResetInput задаёт входные данные операции.
type RequestPasswordResetInput struct {
	Email string
}

// RequestPasswordResetResult содержит результат операции.
type RequestPasswordResetResult struct {
	Success       bool
	ExpiresAtUnix int64
}

// ResetPasswordInput задаёт входные данные операции.
type ResetPasswordInput struct {
	Token       string
	NewPassword string
}

// ResetPasswordResult содержит результат операции.
type ResetPasswordResult struct {
	Success                  bool
	InvalidatedSessionsCount int32
}
