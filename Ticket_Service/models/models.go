package models

import (
	"time"

	"github.com/google/uuid"
)

type TicketStatus string

const (
	TicketStatusNew        TicketStatus = "NEW"
	TicketStatusAssigned   TicketStatus = "ASSIGNED"
	TicketStatusInProgress TicketStatus = "IN_PROGRESS"
	TicketStatusDone       TicketStatus = "DONE"
	TicketStatusCanceled   TicketStatus = "CANCELED"
)

func (s TicketStatus) IsValid() bool {
	switch s {
	case TicketStatusNew,
		TicketStatusAssigned,
		TicketStatusInProgress,
		TicketStatusDone,
		TicketStatusCanceled:
		return true
	default:
		return false
	}
}

type TicketPriority string

const (
	TicketPriorityLow       TicketPriority = "LOW"
	TicketPriorityMedium    TicketPriority = "MEDIUM"
	TicketPriorityHigh      TicketPriority = "HIGH"
	TicketPriorityEmergency TicketPriority = "EMERGENCY"
)

func (p TicketPriority) IsValid() bool {
	switch p {
	case TicketPriorityLow,
		TicketPriorityMedium,
		TicketPriorityHigh,
		TicketPriorityEmergency:
		return true
	default:
		return false
	}
}

type TicketSortBy string

const (
	TicketSortByCreatedAt TicketSortBy = "created_at"
	TicketSortByUpdatedAt TicketSortBy = "updated_at"
	TicketSortByPriority  TicketSortBy = "priority"
	TicketSortByStatus    TicketSortBy = "status"
)

func (s TicketSortBy) IsValid() bool {
	switch s {
	case TicketSortByCreatedAt,
		TicketSortByUpdatedAt,
		TicketSortByPriority,
		TicketSortByStatus:
		return true
	default:
		return false
	}
}

type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
)

func (s SortOrder) IsValid() bool {
	switch s {
	case SortOrderAsc, SortOrderDesc:
		return true
	default:
		return false
	}
}

type Ticket struct {
	ID           uuid.UUID `json:"id"`
	DepartmentID uuid.UUID `json:"department_id"`
	CategoryID   uuid.UUID `json:"category_id"`

	UserID    uuid.UUID  `json:"user_id"`
	BrigadeID *uuid.UUID `json:"brigade_id,omitempty"`

	Title       string         `json:"title"`
	Description string         `json:"description"`
	Status      TicketStatus   `json:"status"`
	Priority    TicketPriority `json:"priority"`

	Address   string  `json:"address"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`

	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	AssignedAt  *time.Time `json:"assigned_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	CanceledAt  *time.Time `json:"canceled_at,omitempty"`
}

type TicketCategory struct {
	ID          uuid.UUID `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type TicketStatusHistory struct {
	ID       uuid.UUID `json:"id"`
	TicketID uuid.UUID `json:"ticket_id"`

	OldStatus *TicketStatus `json:"old_status,omitempty"`
	NewStatus TicketStatus  `json:"new_status"`

	ChangedBy *uuid.UUID `json:"changed_by,omitempty"`
	Comment   *string    `json:"comment,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

type CreateTicketInput struct {
	DepartmentID uuid.UUID
	CategoryID   uuid.UUID
	UserID       uuid.UUID

	Title       string
	Description string
	Priority    TicketPriority

	Address   string
	Latitude  float64
	Longitude float64
}

type CreateTicketResult struct {
	Ticket *Ticket
}

type GetTicketInput struct {
	TicketID uuid.UUID
}

type GetTicketResult struct {
	Ticket *Ticket
}

type ListTicketsInput struct {
	DepartmentID *uuid.UUID
	UserID       *uuid.UUID
	BrigadeID    *uuid.UUID
	CategoryID   *uuid.UUID

	Status   *TicketStatus
	Priority *TicketPriority

	CreatedFrom *time.Time
	CreatedTo   *time.Time

	SortBy    TicketSortBy
	SortOrder SortOrder

	Limit  int32
	Offset int32
}

type ListTicketsResult struct {
	Tickets []*Ticket
	Total   int64
}

type UpdateTicketInput struct {
	TicketID uuid.UUID

	Title       *string
	Description *string
	CategoryID  *uuid.UUID
	Priority    *TicketPriority

	Address   *string
	Latitude  *float64
	Longitude *float64

	UpdatedBy *uuid.UUID
}

type UpdateTicketResult struct {
	Ticket *Ticket
}

type ChangeTicketStatusInput struct {
	TicketID  uuid.UUID
	NewStatus TicketStatus
	ChangedBy uuid.UUID
	Comment   *string
}

type ChangeTicketStatusResult struct {
	Ticket *Ticket
}

type AssignBrigadeInput struct {
	TicketID   uuid.UUID
	BrigadeID  uuid.UUID
	AssignedBy uuid.UUID
	Comment    *string
}

type AssignBrigadeResult struct {
	Ticket *Ticket
}

type CancelTicketInput struct {
	TicketID   uuid.UUID
	CanceledBy uuid.UUID
	Reason     string
}

type CancelTicketResult struct {
	Ticket *Ticket
}

type CompleteTicketInput struct {
	TicketID    uuid.UUID
	CompletedBy uuid.UUID
	Comment     *string
}

type CompleteTicketResult struct {
	Ticket *Ticket
}

type GetTicketStatusHistoryInput struct {
	TicketID uuid.UUID
	Limit    int32
	Offset   int32
}

type GetTicketStatusHistoryResult struct {
	History []*TicketStatusHistory
	Total   int64
}

type CreateCategoryInput struct {
	Code        string
	Name        string
	Description *string
}

type CreateCategoryResult struct {
	Category *TicketCategory
}

type GetCategoryInput struct {
	CategoryID uuid.UUID
}

type GetCategoryResult struct {
	Category *TicketCategory
}

type ListCategoriesInput struct {
	OnlyActive bool
	Limit      int32
	Offset     int32
}

type ListCategoriesResult struct {
	Categories []*TicketCategory
	Total      int64
}

type UpdateCategoryInput struct {
	CategoryID uuid.UUID

	Name        *string
	Description *string
	IsActive    *bool
}

type UpdateCategoryResult struct {
	Category *TicketCategory
}

type DeleteCategoryInput struct {
	CategoryID uuid.UUID
}

type DeleteCategoryResult struct {
	Category *TicketCategory
}
