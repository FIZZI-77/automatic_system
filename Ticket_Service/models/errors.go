package models

import "errors"

var (
	ErrValidation              = errors.New("validation failed")
	ErrNotFound                = errors.New("not found")
	ErrAlreadyExists           = errors.New("already exists")
	ErrCategoryInactive        = errors.New("category is not active")
	ErrInvalidStatusTransition = errors.New("invalid status transition")
	ErrTicketTerminalState     = errors.New("ticket is already in terminal state")
)
