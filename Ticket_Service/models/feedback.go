package models

import (
	"time"

	"github.com/google/uuid"
)

// TicketFeedback описывает доменную модель.
type TicketFeedback struct {
	TicketID        uuid.UUID
	UserID          uuid.UUID
	Rating          uint32
	ProblemResolved bool
	Comment         string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// SubmitTicketFeedbackInput задаёт входные данные операции.
type SubmitTicketFeedbackInput struct {
	TicketID        uuid.UUID
	UserID          uuid.UUID
	Rating          uint32
	ProblemResolved bool
	Comment         string
}

// GetTicketFeedbackInput задаёт входные данные операции.
type GetTicketFeedbackInput struct {
	TicketID   uuid.UUID
	ActorID    uuid.UUID
	Privileged bool
}
