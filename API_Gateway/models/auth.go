package models

// RegisterRequest содержит параметры API-запроса.
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	Username string `json:"username" binding:"required,min=3,max=50"`
}

// RegisterResponse содержит данные API-ответа.
type RegisterResponse struct {
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// LoginRequest содержит параметры API-запроса.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	ClientID string `json:"client_id"`
}

// LoginResponse содержит данные API-ответа.
type LoginResponse struct {
	AccessToken          string `json:"access_token"`
	RefreshToken         string `json:"refresh_token"`
	AccessExpiresAtUnix  int64  `json:"access_expires_at_unix"`
	RefreshExpiresAtUnix int64  `json:"refresh_expires_at_unix"`
	SessionID            string `json:"session_id"`
	TokenType            string `json:"token_type"`
}

// RefreshRequest содержит параметры API-запроса.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	ClientID     string `json:"client_id"`
}

// RefreshResponse содержит данные API-ответа.
type RefreshResponse struct {
	AccessToken          string `json:"access_token"`
	RefreshToken         string `json:"refresh_token"`
	AccessExpiresAtUnix  int64  `json:"access_expires_at_unix"`
	RefreshExpiresAtUnix int64  `json:"refresh_expires_at_unix"`
	SessionID            string `json:"session_id"`
	TokenType            string `json:"token_type"`
}

// LogoutResponse содержит данные API-ответа.
type LogoutResponse struct {
	Success bool `json:"success"`
}

// LogoutAllResponse содержит данные API-ответа.
type LogoutAllResponse struct {
	Success      bool   `json:"success"`
	RevokedCount uint32 `json:"revoked_count"`
}

// MeResponse содержит данные API-ответа.
type MeResponse struct {
	UserID        string   `json:"user_id"`
	Email         string   `json:"email"`
	Roles         []string `json:"roles"`
	Permissions   []string `json:"permissions"`
	IsActive      bool     `json:"is_active"`
	EmailVerified bool     `json:"email_verified"`
}

// ChangePasswordRequest содержит параметры API-запроса.
type ChangePasswordRequest struct {
	OldPassword         string `json:"old_password" binding:"required"`
	NewPassword         string `json:"new_password" binding:"required,min=8"`
	RevokeOtherSessions bool   `json:"revoke_other_sessions"`
}

// ChangePasswordResponse содержит данные API-ответа.
type ChangePasswordResponse struct {
	Success                  bool   `json:"success"`
	InvalidatedSessionsCount uint32 `json:"invalidated_sessions_count"`
}

// SendVerificationEmailRequest содержит параметры API-запроса.
type SendVerificationEmailRequest struct {
	Email string `json:"email" binding:"omitempty,email"`
}

// SendVerificationEmailResponse содержит данные API-ответа.
type SendVerificationEmailResponse struct {
	Success       bool  `json:"success"`
	ExpiresAtUnix int64 `json:"expires_at_unix"`
}

// VerifyEmailRequest содержит параметры API-запроса.
type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

// VerifyEmailResponse содержит данные API-ответа.
type VerifyEmailResponse struct {
	Success       bool   `json:"success"`
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Message       string `json:"message"`
}

// RequestPasswordResetRequest содержит параметры API-запроса.
type RequestPasswordResetRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// RequestPasswordResetResponse содержит данные API-ответа.
type RequestPasswordResetResponse struct {
	Success       bool  `json:"success"`
	ExpiresAtUnix int64 `json:"expires_at_unix"`
}

// ResetPasswordRequest содержит параметры API-запроса.
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// ResetPasswordResponse содержит данные API-ответа.
type ResetPasswordResponse struct {
	Success                  bool   `json:"success"`
	InvalidatedSessionsCount uint32 `json:"invalidated_sessions_count"`
}

// ErrorResponse содержит данные API-ответа.
type ErrorResponse struct {
	Error string `json:"error"`
}

// ValidationErrorResponse содержит данные API-ответа.
type ValidationErrorResponse struct {
	Error   string            `json:"error"`
	Details map[string]string `json:"details,omitempty"`
}
