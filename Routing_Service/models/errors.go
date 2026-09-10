package models

import "errors"

var (
	ErrInvalidArgument       = errors.New("invalid argument")
	ErrNotFound              = errors.New("not found")
	ErrConflict              = errors.New("conflict")
	ErrDependencyUnavailable = errors.New("dependency unavailable")
)
