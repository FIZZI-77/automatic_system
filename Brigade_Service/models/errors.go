package models

import "errors"

var (
	ErrValidation            = errors.New("validation error")
	ErrNotFound              = errors.New("not found")
	ErrAlreadyExists         = errors.New("already exists")
	ErrPermissionDenied      = errors.New("permission denied")
	ErrInvalidStatus         = errors.New("invalid status")
	ErrInvalidRole           = errors.New("invalid role")
	ErrInvalidAvailability   = errors.New("invalid availability status")
	ErrInvalidGeometry       = errors.New("invalid geometry")
	ErrScheduleConflict      = errors.New("schedule conflict")
	ErrBrigadeUnavailable    = errors.New("brigade unavailable")
	ErrBrigadeCannotHandle   = errors.New("brigade cannot handle ticket")
	ErrDepartmentInactive    = errors.New("department is not active")
	ErrDependencyUnavailable = errors.New("required dependency is unavailable")
	ErrIdempotencyConflict   = errors.New("idempotency key reused with different request")
	ErrIdempotencyInProgress = errors.New("idempotent operation is still processing")
	ErrIdempotencyFailed     = errors.New("idempotent operation failed previously")
)
