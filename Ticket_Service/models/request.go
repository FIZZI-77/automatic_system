package models

import (
	"time"

	"github.com/google/uuid"
)

const (
	DuplicateRadiusMeters = 100.0
	DuplicateWindow       = 24 * time.Hour
)

type TicketType string

const (
	TicketTypeIncident TicketType = "INCIDENT"
	TicketTypeRequest  TicketType = "REQUEST"
)

func (t TicketType) IsValid() bool {
	switch t {
	case TicketTypeIncident, TicketTypeRequest:
		return true
	default:
		return false
	}
}

type CreateRequestInput struct {
	DepartmentID uuid.UUID
	CategoryID   uuid.UUID
	UserID       uuid.UUID

	Title       string
	Description string
	Priority    TicketPriority

	Address   string
	Latitude  float64
	Longitude float64
	AssetID   *uuid.UUID

	ExternalSystemID *uuid.UUID
	ExternalID       *string
}

type CreateRequestResult struct {
	Request          *Ticket
	Incident         *Ticket
	DuplicateMatched bool
}

type AttachRequestInput struct {
	IncidentID uuid.UUID
	RequestID  uuid.UUID
	ChangedBy  uuid.UUID
	Reason     string

	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

type DetachRequestInput struct {
	RequestID uuid.UUID
	ChangedBy uuid.UUID
	Reason    string

	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

type ListIncidentRequestsInput struct {
	IncidentID uuid.UUID
	Limit      int32
	Offset     int32

	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}
