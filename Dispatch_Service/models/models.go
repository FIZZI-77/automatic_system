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

type Status string
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

type Operation struct {
	ID            uuid.UUID
	TicketID      uuid.UUID
	DepartmentID  *uuid.UUID
	CategoryID    *uuid.UUID
	Priority      string
	BrigadeID     *uuid.UUID
	RouteID       *uuid.UUID
	Mode          Mode
	Status        Status
	Version       int32
	RequestedBy   uuid.UUID
	FailureReason *string
	FailureCode   *string
	FailureStage  *string
	ExpiresAt     time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type CreateOperationInput struct {
	TicketID       uuid.UUID
	DepartmentID   uuid.UUID
	CategoryID     uuid.UUID
	Priority       string
	RequestedBy    uuid.UUID
	Mode           Mode
	TTL            time.Duration
	TriggerEventID *uuid.UUID
}

type Candidate struct {
	BrigadeID      uuid.UUID
	Rank           int32
	DistanceMeters float64
	ETASeconds     int64
	Reachable      bool
	Latitude       float64
	Longitude      float64
}

type RecommendInput struct {
	TicketID         uuid.UUID
	RequiredSkillIDs []uuid.UUID
	Limit            int32
}

type ReserveInput struct {
	TicketID         uuid.UUID
	BrigadeID        uuid.UUID
	RequiredSkillIDs []uuid.UUID
	RequestedBy      uuid.UUID
	TTL              time.Duration
}

type ConfirmInput struct {
	ID              uuid.UUID
	ConfirmedBy     uuid.UUID
	ExpectedVersion int32
}

type AutoInput struct {
	TicketID         uuid.UUID
	RequiredSkillIDs []uuid.UUID
	RequestedBy      uuid.UUID
	CandidateLimit   int32
	TriggerEventID   *uuid.UUID
}

type CancelInput struct {
	ID              uuid.UUID
	CancelledBy     uuid.UUID
	ExpectedVersion int32
	Reason          string
}
type ListInput struct {
	TicketID  *uuid.UUID
	BrigadeID *uuid.UUID
	Status    *Status
	Limit     int32
	Offset    int32
}
