package models

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	Username string `json:"username" binding:"required,min=3,max=50"`
}

type RegisterResponse struct {
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	ClientID string `json:"client_id"`
}

type LoginResponse struct {
	AccessToken          string `json:"access_token"`
	RefreshToken         string `json:"refresh_token"`
	AccessExpiresAtUnix  int64  `json:"access_expires_at_unix"`
	RefreshExpiresAtUnix int64  `json:"refresh_expires_at_unix"`
	SessionID            string `json:"session_id"`
	TokenType            string `json:"token_type"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	ClientID     string `json:"client_id"`
}

type RefreshResponse struct {
	AccessToken          string `json:"access_token"`
	RefreshToken         string `json:"refresh_token"`
	AccessExpiresAtUnix  int64  `json:"access_expires_at_unix"`
	RefreshExpiresAtUnix int64  `json:"refresh_expires_at_unix"`
	SessionID            string `json:"session_id"`
	TokenType            string `json:"token_type"`
}

type LogoutResponse struct {
	Success bool `json:"success"`
}

type LogoutAllResponse struct {
	Success      bool   `json:"success"`
	RevokedCount uint32 `json:"revoked_count"`
}

type MeResponse struct {
	UserID        string   `json:"user_id"`
	Email         string   `json:"email"`
	Roles         []string `json:"roles"`
	Permissions   []string `json:"permissions"`
	IsActive      bool     `json:"is_active"`
	EmailVerified bool     `json:"email_verified"`
}

type ChangePasswordRequest struct {
	OldPassword         string `json:"old_password" binding:"required"`
	NewPassword         string `json:"new_password" binding:"required,min=8"`
	RevokeOtherSessions bool   `json:"revoke_other_sessions"`
}

type ChangePasswordResponse struct {
	Success                  bool   `json:"success"`
	InvalidatedSessionsCount uint32 `json:"invalidated_sessions_count"`
}

type SendVerificationEmailRequest struct {
	Email string `json:"email" binding:"omitempty,email"`
}

type SendVerificationEmailResponse struct {
	Success       bool  `json:"success"`
	ExpiresAtUnix int64 `json:"expires_at_unix"`
}

type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

type VerifyEmailResponse struct {
	Success       bool   `json:"success"`
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Message       string `json:"message"`
}

type RequestPasswordResetRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type RequestPasswordResetResponse struct {
	Success       bool  `json:"success"`
	ExpiresAtUnix int64 `json:"expires_at_unix"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

type ResetPasswordResponse struct {
	Success                  bool   `json:"success"`
	InvalidatedSessionsCount uint32 `json:"invalidated_sessions_count"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type ValidationErrorResponse struct {
	Error   string            `json:"error"`
	Details map[string]string `json:"details,omitempty"`
}
