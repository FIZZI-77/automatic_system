package models

import "errors"

var (
	ErrValidation            = errors.New("validation error")
	ErrNotFound              = errors.New("not found")
	ErrAlreadyExists         = errors.New("already exists")
	ErrPermissionDenied      = errors.New("permission denied")
	ErrOutOfOrderPosition    = errors.New("position sequence is out of order")
	ErrInvalidGeometry       = errors.New("invalid geometry")
	ErrDependencyUnavailable = errors.New("required dependency is unavailable")
	ErrPositionBufferFull    = errors.New("position history buffer is full")
)
