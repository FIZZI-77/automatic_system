package models

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidArgument = errors.New("invalid argument")
	ErrNotFound        = errors.New("not found")
	ErrConflict        = errors.New("conflict")
	ErrForbidden       = errors.New("forbidden")
)

// Status задаёт допустимое состояние модели.
type Status string
// Mode задаёт режим выполнения операции.
type Mode string

const (
	ModeManual    Mode = "MANUAL"
	ModeAutomatic Mode = "AUTOMATIC"
)

const (
	StatusPending    Status = "PENDING"
	StatusReserved   Status = "RESERVED"
	StatusConfirming Status = "CONFIRMING"
	StatusAssigned   Status = "ASSIGNED"
	StatusFailed     Status = "FAILED"
	StatusCancelled  Status = "CANCELLED"
	StatusExpired    Status = "EXPIRED"
)

// Operation описывает операцию диспетчеризации заявки.
type Operation struct {
	ID                uuid.UUID
	TicketID          uuid.UUID
	DepartmentID      *uuid.UUID
	CategoryID        *uuid.UUID
	Priority          string
	BrigadeID         *uuid.UUID
	RouteID           *uuid.UUID
	Mode              Mode
	Status            Status
	Version           int32
	RequestedBy       uuid.UUID
	FailureReason     *string
	FailureCode       *string
	FailureStage      *string
	ExpiresAt         time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	ReleasePending    bool
	ReleaseActorID    *uuid.UUID
	AssignmentComment string
}

// CreateOperationInput задаёт входные данные операции.
type CreateOperationInput struct {
	TicketID          uuid.UUID
	DepartmentID      uuid.UUID
	CategoryID        uuid.UUID
	Priority          string
	RequestedBy       uuid.UUID
	Mode              Mode
	TTL               time.Duration
	TriggerEventID    *uuid.UUID
	AssignmentComment string
}

// Candidate описывает доменную модель.
type Candidate struct {
	BrigadeID      uuid.UUID
	Rank           int32
	DistanceMeters float64
	ETASeconds     int64
	Reachable      bool
	Latitude       float64
	Longitude      float64
}

// RecommendInput задаёт входные данные операции.
type RecommendInput struct {
	TicketID         uuid.UUID
	RequiredSkillIDs []uuid.UUID
	Limit            int32
}

// ReserveInput задаёт входные данные операции.
type ReserveInput struct {
	TicketID         uuid.UUID
	BrigadeID        uuid.UUID
	RequiredSkillIDs []uuid.UUID
	RequestedBy      uuid.UUID
	TTL              time.Duration
}

// ConfirmInput задаёт входные данные операции.
type ConfirmInput struct {
	ID              uuid.UUID
	ConfirmedBy     uuid.UUID
	ExpectedVersion int32
}

// AutoInput задаёт входные данные операции.
type AutoInput struct {
	TicketID         uuid.UUID
	RequiredSkillIDs []uuid.UUID
	RequestedBy      uuid.UUID
	CandidateLimit   int32
	TriggerEventID   *uuid.UUID
}

// CancelInput задаёт входные данные операции.
type CancelInput struct {
	ID              uuid.UUID
	CancelledBy     uuid.UUID
	ExpectedVersion int32
	Reason          string
}
// ListInput задаёт входные данные операции.
type ListInput struct {
	DepartmentID *uuid.UUID
	TicketID     *uuid.UUID
	BrigadeID    *uuid.UUID
	Status       *Status
	Limit        int32
	Offset       int32
}
