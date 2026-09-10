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
	ID                           uuid.UUID
	Name                         string
	DepartmentID, CategoryID     *uuid.UUID
	Priority                     *Priority
	ResponseTime, ResolutionTime time.Duration
	WarningPercent               int32
	Active                       bool
	CreatedAt, UpdatedAt         time.Time
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
	ID, TicketID, RuleID, DepartmentID, CategoryID                                   uuid.UUID
	Priority                                                                         Priority
	Status                                                                           Status
	ResponseDeadline, ResolutionDeadline                                             time.Time
	RespondedAt, CompletedAt                                                         *time.Time
	ResponseBreached, ResolutionBreached, ResponseWarningSent, ResolutionWarningSent bool
	Version                                                                          int32
	CreatedAt, UpdatedAt                                                             time.Time
}
type History struct {
	ID, TicketSLAID, TicketID uuid.UUID
	EventType                 EventType
	OccurredAt                time.Time
	Details                   string
}
type TicketEvent struct {
	EventID, EventType                 string
	TicketID, DepartmentID, CategoryID uuid.UUID
	Priority                           Priority
	Status                             string
	CreatedAt, UpdatedAt               time.Time
}
type RuleFilter struct {
	DepartmentID, CategoryID *uuid.UUID
	Priority                 *Priority
	Active                   *bool
	Limit, Offset            int32
}
type SLAFilter struct {
	DepartmentID  *uuid.UUID
	Status        *Status
	Breached      *bool
	Limit, Offset int32
}
