package models

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Type задаёт тип доменной модели.
type Type string

// Format описывает доменную модель.
type Format string

// Status задаёт допустимое состояние модели.
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

// Filter задаёт условия фильтрации.
type Filter struct {
	From         *time.Time
	To           *time.Time
	DepartmentID *string
	CategoryID   *string
	Priority     *string
}

// Report описывает задание на формирование отчёта.
type Report struct {
	ID          uuid.UUID
	RequestedBy uuid.UUID
	Name        string
	Type        Type
	Format      Format
	Status      Status
	Filter      Filter
	ActorRoles  []string
	FileID      *uuid.UUID
	Error       *string
	Attempts    int32
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CompletedAt *time.Time
}

// CreateInput задаёт входные данные операции.
type CreateInput struct {
	RequestedBy uuid.UUID
	Name        string
	Type        Type
	Format      Format
	Filter      Filter
	ActorRoles  []string
}

// ListFilter задаёт условия фильтрации.
type ListFilter struct {
	RequestedBy *uuid.UUID
	Status      *Status
	Limit       int32
	Offset      int32
}

// Artifact описывает доменную модель.
type Artifact struct {
	Name        string
	ContentType string
	Data        []byte
}

// CompletionReport хранит неизменяемый снимок для формирования итогового акта
// по завершённой заявке. Gateway разрешает имена до передачи снимка в Report
// Service, поэтому PDF воспроизводим даже после изменения профилей.
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

// CompletionTicket описывает доменную модель.
type CompletionTicket struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Address string `json:"address"`
}

// CompletionBrigade описывает доменную модель.
type CompletionBrigade struct {
	ID      string                    `json:"id"`
	Name    string                    `json:"name"`
	Members []CompletionBrigadeMember `json:"members"`
}

// CompletionBrigadeMember описывает доменную модель.
type CompletionBrigadeMember struct {
	UserID   string `json:"user_id"`
	FullName string `json:"full_name"`
	Role     string `json:"role"`
}

// EmbeddedImage описывает доменную модель.
type EmbeddedImage struct {
	Name        string
	ContentType string
	Data        []byte
}

// CompletionReportResult содержит результат операции.
type CompletionReportResult struct {
	FileID string `json:"file_id"`
	Name   string `json:"name"`
}

// CompletionCompensation описывает доменную модель.
type CompletionCompensation struct {
	WorkReportID string   `json:"work_report_id"`
	FileID       string   `json:"file_id"`
	RequestedBy  string   `json:"requested_by"`
	ActorRoles   []string `json:"actor_roles"`
}

// Download описывает доменную модель.
type Download struct {
	Report    *Report
	URL       string
	ExpiresAt time.Time
}

// Validate проверяет ненулевого инициатора, имя длиной 3–160 байт, поддерживаемые
// тип и формат отчёта, а также порядок дат фильтра. Исходные данные не изменяет.
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
