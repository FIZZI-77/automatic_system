package models

import "time"

type SubmitTicketFeedbackRequest struct {
	TicketID        string `json:"ticket_id" binding:"required,uuid"`
	Rating          uint32 `json:"rating" binding:"required,min=1,max=5"`
	ProblemResolved bool   `json:"problem_resolved"`
	Comment         string `json:"comment" binding:"max=1000"`
}

type GetTicketFeedbackRequest struct {
	TicketID string `json:"ticket_id" binding:"required,uuid"`
}

type TicketFeedback struct {
	TicketID        string    `json:"ticket_id"`
	UserID          string    `json:"user_id"`
	Rating          uint32    `json:"rating"`
	ProblemResolved bool      `json:"problem_resolved"`
	Comment         string    `json:"comment"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}
