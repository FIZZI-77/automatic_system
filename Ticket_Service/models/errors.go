package models

import "errors"

var (
	ErrValidation              = errors.New("validation failed")
	ErrNotFound                = errors.New("not found")
	ErrAlreadyExists           = errors.New("already exists")
	ErrPermissionDenied        = errors.New("permission denied")
	ErrCategoryInactive        = errors.New("category is not active")
	ErrInvalidStatusTransition = errors.New("invalid status transition")
	ErrTicketTerminalState     = errors.New("ticket is already in terminal state")
	ErrIdempotencyConflict     = errors.New("idempotency key reused with different request")
	ErrIdempotencyInProgress   = errors.New("idempotent operation is still processing")
	ErrIdempotencyFailed       = errors.New("idempotent operation failed previously")
)
