package models

import (
	"github.com/google/uuid"
	"time"
)

type TokenType string

const (
	TokenTypeEmailVerification TokenType = "email_verification"
	TokenTypePasswordReset     TokenType = "password_reset"
)

type OneTimeToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	Type      TokenType
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

type RegisterInput struct {
	Email    string
	Password string
	Username string
}

type RegisterResult struct {
	UserID        string
	Email         string
	EmailVerified bool
}

type LoginInput struct {
	Email     string
	Password  string
	ClientID  string
	IP        string
	UserAgent string
}

type LoginResult struct {
	AccessToken          string
	RefreshToken         string
	AccessExpiresAtUnix  int64
	RefreshExpiresAtUnix int64
	SessionID            uuid.UUID
	TokenType            string
}

type RefreshInput struct {
	RefreshToken string
	ClientID     string
	IP           string
	UserAgent    string
}

type RefreshResult struct {
	AccessToken          string
	RefreshToken         string
	AccessExpiresAtUnix  int64
	RefreshExpiresAtUnix int64
	SessionID            uuid.UUID
	TokenType            string
}

type LogoutInput struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
}

type LogoutAllInput struct {
	UserID uuid.UUID
}

type UserAuthInfo struct {
	UserID        uuid.UUID
	Email         string
	Roles         []string
	Permissions   []string
	IsActive      bool
	EmailVerified bool
}

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

type ChangePasswordInput struct {
	UserID              uuid.UUID
	OldPassword         string
	NewPassword         string
	SessionID           uuid.UUID
	RevokeOtherSessions bool
}

type ChangePasswordResult struct {
	Success                  bool
	InvalidatedSessionsCount int32
}

type SendVerificationEmailInput struct {
	UserID uuid.UUID
	Email  string
}

type SendVerificationEmailResult struct {
	Success       bool
	ExpiresAtUnix int64
}

type VerifyEmailInput struct {
	Token string
}

type VerifyEmailResult struct {
	Success       bool
	UserID        uuid.UUID
	Email         string
	EmailVerified bool
	Message       string
}

type RequestPasswordResetInput struct {
	Email string
}
type RequestPasswordResetResult struct {
	Success       bool
	ExpiresAtUnix int64
}
type ResetPasswordInput struct {
	Token       string
	NewPassword string
}
type ResetPasswordResult struct {
	Success                  bool
	InvalidatedSessionsCount int32
}
