package models

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

type Type string
type Format string
type Status string

const (
	TypeTicketOverview  Type   = "TICKET_OVERVIEW"
	TypeSLASummary      Type   = "SLA_SUMMARY"
	TypeTicketBreakdown Type   = "TICKET_BREAKDOWN"
	TypeDailyTickets    Type   = "DAILY_TICKETS"
	FormatPDF           Format = "PDF"
	FormatXLSX          Format = "XLSX"
	FormatCSV           Format = "CSV"
	StatusPending       Status = "PENDING"
	StatusProcessing    Status = "PROCESSING"
	StatusCompleted     Status = "COMPLETED"
	StatusFailed        Status = "FAILED"
	StatusCanceled      Status = "CANCELED"
)

var ErrForbidden = errors.New("permission denied")
var ErrInvalidState = errors.New("invalid report state")

type Filter struct {
	From, To                           *time.Time
	DepartmentID, CategoryID, Priority *string
}
type Report struct {
	ID, RequestedBy      uuid.UUID
	Name                 string
	Type                 Type
	Format               Format
	Status               Status
	Filter               Filter
	ActorRoles           []string
	FileID               *uuid.UUID
	Error                *string
	Attempts             int32
	CreatedAt, UpdatedAt time.Time
	CompletedAt          *time.Time
}
type CreateInput struct {
	RequestedBy uuid.UUID
	Name        string
	Type        Type
	Format      Format
	Filter      Filter
	ActorRoles  []string
}
type ListFilter struct {
	RequestedBy   *uuid.UUID
	Status        *Status
	Limit, Offset int32
}
type Artifact struct {
	Name, ContentType string
	Data              []byte
}
type Download struct {
	Report    *Report
	URL       string
	ExpiresAt time.Time
}

func (v CreateInput) Validate() error {
	if v.RequestedBy == uuid.Nil || len(v.Name) < 3 || len(v.Name) > 160 {
		return errors.New("invalid report name or requester")
	}
	switch v.Type {
	case TypeTicketOverview, TypeSLASummary, TypeTicketBreakdown, TypeDailyTickets:
	default:
		return errors.New("unsupported report type")
	}
	switch v.Format {
	case FormatPDF, FormatXLSX, FormatCSV:
	default:
		return errors.New("unsupported report format")
	}
	if v.Filter.From != nil && v.Filter.To != nil && v.Filter.From.After(*v.Filter.To) {
		return errors.New("filter from must not be after to")
	}
	return nil
}
