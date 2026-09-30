package models

import (
	"time"

	"github.com/google/uuid"
)

type TicketFeedback struct {
	TicketID        uuid.UUID
	UserID          uuid.UUID
	Rating          uint32
	ProblemResolved bool
	Comment         string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type SubmitTicketFeedbackInput struct {
	TicketID        uuid.UUID
	UserID          uuid.UUID
	Rating          uint32
	ProblemResolved bool
	Comment         string
}

type GetTicketFeedbackInput struct {
	TicketID   uuid.UUID
	ActorID    uuid.UUID
	Privileged bool
}
