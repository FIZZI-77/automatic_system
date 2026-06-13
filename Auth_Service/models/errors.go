package models

import "errors"

var (
	ErrUserAlreadyExists     = errors.New("user already exists")
	ErrUserNotFound          = errors.New("user not found")
	ErrUserInactive          = errors.New("user is not active")
	ErrInvalidPassword       = errors.New("invalid password")
	ErrInvalidOldPassword    = errors.New("invalid old password")
	ErrInvalidRefreshToken   = errors.New("invalid refresh token")
	ErrRefreshTokenExpired   = errors.New("refresh token expired")
	ErrRefreshTokenReplaced  = errors.New("refresh token replaced")
	ErrSessionNotFound       = errors.New("session not found")
	ErrSessionExpired        = errors.New("session expired")
	ErrInvalidSession        = errors.New("invalid session")
	ErrEmailAlreadyVerified  = errors.New("email already verified")
	ErrInvalidToken          = errors.New("invalid token")
	ErrTokenAlreadyUsed      = errors.New("token already used")
	ErrTokenExpired          = errors.New("token expired")
	ErrIdempotencyConflict   = errors.New("idempotency key reused with different request")
	ErrIdempotencyInProgress = errors.New("idempotent operation is still processing")
	ErrIdempotencyFailed     = errors.New("idempotent operation failed previously")
)
