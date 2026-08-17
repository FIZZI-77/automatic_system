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

// CompletionReport is the immutable snapshot used to build the final act for
// one completed ticket. Names are resolved by the gateway before this snapshot
// reaches Report Service so the PDF remains reproducible even if profiles are
// edited later.
type CompletionReport struct {
	WorkReportID string            `json:"work_report_id"`
	RequestedBy  string            `json:"requested_by"`
	ActorRoles   []string          `json:"actor_roles"`
	Ticket       CompletionTicket  `json:"ticket"`
	Brigade      CompletionBrigade `json:"brigade"`
	OpenedBy     string            `json:"opened_by"`
	Description  string            `json:"description"`
	FileIDs      []string          `json:"file_ids"`
}

type CompletionTicket struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Address string `json:"address"`
}

type CompletionBrigade struct {
	ID      string                    `json:"id"`
	Name    string                    `json:"name"`
	Members []CompletionBrigadeMember `json:"members"`
}

type CompletionBrigadeMember struct {
	UserID   string `json:"user_id"`
	FullName string `json:"full_name"`
	Role     string `json:"role"`
}

type EmbeddedImage struct {
	Name        string
	ContentType string
	Data        []byte
}

type CompletionReportResult struct {
	FileID string `json:"file_id"`
	Name   string `json:"name"`
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
