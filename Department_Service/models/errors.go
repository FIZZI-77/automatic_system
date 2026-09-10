package models

import "errors"

var (
	ErrValidation            = errors.New("validation error")
	ErrNotFound              = errors.New("not found")
	ErrAlreadyExists         = errors.New("already exists")
	ErrPermissionDenied      = errors.New("permission denied")
	ErrIdempotencyConflict   = errors.New("idempotency key reused with different request")
	ErrIdempotencyInProgress = errors.New("idempotent operation is still processing")
	ErrIdempotencyFailed     = errors.New("idempotent operation failed previously")
)
