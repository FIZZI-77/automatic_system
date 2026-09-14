package models

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound        = errors.New("not found")
	ErrInvalidArgument = errors.New("invalid argument")
	ErrConflict        = errors.New("conflict")
)

type Priority string

const (
	PriorityLow       Priority = "LOW"
	PriorityMedium    Priority = "MEDIUM"
	PriorityHigh      Priority = "HIGH"
	PriorityEmergency Priority = "EMERGENCY"
)

func (p Priority) Valid() bool {
	return p == PriorityLow || p == PriorityMedium || p == PriorityHigh || p == PriorityEmergency
}

type Status string

const (
	StatusActive    Status = "ACTIVE"
	StatusCompleted Status = "COMPLETED"
	StatusCancelled Status = "CANCELLED"
)

type EventType string

const (
	EventCreated            EventType = "CREATED"
	EventResponseRecorded   EventType = "RESPONSE_RECORDED"
	EventResponseWarning    EventType = "RESPONSE_WARNING"
	EventResponseBreached   EventType = "RESPONSE_BREACHED"
	EventResolutionWarning  EventType = "RESOLUTION_WARNING"
	EventResolutionBreached EventType = "RESOLUTION_BREACHED"
	EventRecalculated       EventType = "RECALCULATED"
	EventCompleted          EventType = "COMPLETED"
	EventCancelled          EventType = "CANCELLED"
)

type Rule struct {
	ID             uuid.UUID
	Name           string
	DepartmentID   *uuid.UUID
	CategoryID     *uuid.UUID
	Priority       *Priority
	ResponseTime   time.Duration
	ResolutionTime time.Duration
	WarningPercent int32
	Active         bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (r *Rule) Validate() error {
	if strings.TrimSpace(r.Name) == "" || r.ResponseTime <= 0 || r.ResolutionTime <= 0 || r.ResponseTime > r.ResolutionTime || r.WarningPercent < 1 || r.WarningPercent > 99 {
		return ErrInvalidArgument
	}
	if r.Priority != nil && !r.Priority.Valid() {
		return ErrInvalidArgument
	}
	return nil
}

type TicketSLA struct {
	ID                    uuid.UUID
	TicketID              uuid.UUID
	RuleID                uuid.UUID
	DepartmentID          uuid.UUID
	CategoryID            uuid.UUID
	Priority              Priority
	Status                Status
	ResponseDeadline      time.Time
	ResolutionDeadline    time.Time
	RespondedAt           *time.Time
	CompletedAt           *time.Time
	ResponseBreached      bool
	ResolutionBreached    bool
	ResponseWarningSent   bool
	ResolutionWarningSent bool
	Version               int32
	CreatedAt             time.Time
	UpdatedAt             time.Time
}
type History struct {
	ID          uuid.UUID
	TicketSLAID uuid.UUID
	TicketID    uuid.UUID
	EventType   EventType
	OccurredAt  time.Time
	Details     string
}
type TicketEvent struct {
	EventID      string
	EventType    string
	TicketID     uuid.UUID
	DepartmentID uuid.UUID
	CategoryID   uuid.UUID
	Priority     Priority
	Status       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
type RuleFilter struct {
	DepartmentID *uuid.UUID
	CategoryID   *uuid.UUID
	Priority     *Priority
	Active       *bool
	Limit        int32
	Offset       int32
}
type SLAFilter struct {
	DepartmentID *uuid.UUID
	Status       *Status
	Breached     *bool
	Limit        int32
	Offset       int32
}
