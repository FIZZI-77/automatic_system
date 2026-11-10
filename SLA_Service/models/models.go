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

// Priority задаёт приоритет доменной модели.
type Priority string

const (
	PriorityLow       Priority = "LOW"
	PriorityMedium    Priority = "MEDIUM"
	PriorityHigh      Priority = "HIGH"
	PriorityEmergency Priority = "EMERGENCY"
)

// Valid сообщает, является ли приоритет одним из LOW, MEDIUM, HIGH или EMERGENCY.
func (p Priority) Valid() bool {
	return p == PriorityLow || p == PriorityMedium || p == PriorityHigh || p == PriorityEmergency
}

// Status задаёт допустимое состояние модели.
type Status string

const (
	StatusActive    Status = "ACTIVE"
	StatusCompleted Status = "COMPLETED"
	StatusCancelled Status = "CANCELLED"
)

// EventType задаёт тип доменной модели.
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

// Rule описывает правило SLA и заданные им сроки.
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

// Validate проверяет непустое имя, положительные сроки, время реакции не больше
// времени решения, процент предупреждения 1–99 и заданный приоритет.
// Правило не изменяет; нарушение возвращает как ErrInvalidArgument.
func (r *Rule) Validate() error {

	if strings.TrimSpace(r.Name) == "" || r.ResponseTime <= 0 || r.ResolutionTime <= 0 || r.ResponseTime > r.ResolutionTime || r.WarningPercent < 1 || r.WarningPercent > 99 {
		return ErrInvalidArgument
	}

	if r.Priority != nil && !r.Priority.Valid() {
		return ErrInvalidArgument
	}

	return nil
}

// TicketSLA описывает рассчитанные SLA-сроки конкретной заявки.
type TicketSLA struct {
	ID                    uuid.UUID
	TicketID              uuid.UUID
	RuleID                uuid.UUID
	DepartmentID          uuid.UUID
	CategoryID            uuid.UUID
	Priority              Priority
	Status                Status
	TicketCreatedAt       time.Time
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

// History описывает доменную модель.
type History struct {
	ID          uuid.UUID
	TicketSLAID uuid.UUID
	TicketID    uuid.UUID
	EventType   EventType
	OccurredAt  time.Time
	Details     string
}

// TicketEvent описывает событие ticket.
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

// RuleFilter задаёт условия фильтрации.
type RuleFilter struct {
	DepartmentID *uuid.UUID
	CategoryID   *uuid.UUID
	Priority     *Priority
	Active       *bool
	Limit        int32
	Offset       int32
}

// SLAFilter задаёт условия фильтрации.
type SLAFilter struct {
	DepartmentID *uuid.UUID
	Status       *Status
	Breached     *bool
	Limit        int32
	Offset       int32
}
