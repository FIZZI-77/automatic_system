package models

import "errors"

var (
	ErrValidation                 = errors.New("validation error")
	ErrNotFound                   = errors.New("not found")
	ErrAlreadyExists              = errors.New("already exists")
	ErrPermissionDenied           = errors.New("permission denied")
	ErrInvalidStatus              = errors.New("invalid work profile status")
	ErrInvalidCertificationStatus = errors.New("invalid certification status")
	ErrInvalidContactMethod       = errors.New("invalid preferred contact method")
	ErrWorkProfileMissing         = errors.New("work profile is missing")
	ErrWorkProfileInactive        = errors.New("work profile is inactive")
	ErrDepartmentMismatch         = errors.New("work profile department does not match target department")
	ErrIdempotencyConflict        = errors.New("idempotency key reused with different request")
	ErrIdempotencyInProgress      = errors.New("idempotent operation is still processing")
	ErrIdempotencyFailed          = errors.New("idempotent operation failed previously")
)
