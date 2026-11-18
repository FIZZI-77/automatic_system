package models

import (
	"time"

	"github.com/google/uuid"
)

// TicketStatus задаёт допустимое состояние модели.
type TicketStatus string

const (
	TicketStatusNew        TicketStatus = "NEW"
	TicketStatusAssigned   TicketStatus = "ASSIGNED"
	TicketStatusInProgress TicketStatus = "IN_PROGRESS"
	TicketStatusDone       TicketStatus = "DONE"
	TicketStatusCanceled   TicketStatus = "CANCELED"
)

// IsValid проверяет принадлежность статуса публичному жизненному циклу заявки.
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

// TicketPriority задаёт приоритет доменной модели.
type TicketPriority string

const (
	TicketPriorityLow       TicketPriority = "LOW"
	TicketPriorityMedium    TicketPriority = "MEDIUM"
	TicketPriorityHigh      TicketPriority = "HIGH"
	TicketPriorityEmergency TicketPriority = "EMERGENCY"
)

// IsValid сообщает, поддерживается ли указанный приоритет заявки.
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

// TicketSortBy задаёт поле сортировки.
type TicketSortBy string

const (
	TicketSortByCreatedAt TicketSortBy = "created_at"
	TicketSortByUpdatedAt TicketSortBy = "updated_at"
	TicketSortByPriority  TicketSortBy = "priority"
	TicketSortByStatus    TicketSortBy = "status"
)

// IsValid проверяет, разрешено ли указанное поле для сортировки заявок.
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

// SortOrder задаёт направление сортировки результатов.
type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
)

// IsValid допускает только поддерживаемые направления сортировки.
func (s SortOrder) IsValid() bool {
	switch s {
	case SortOrderAsc, SortOrderDesc:
		return true
	default:
		return false
	}
}

// Ticket описывает заявку и её текущее состояние.
type Ticket struct {
	ID           uuid.UUID  `json:"id"`
	DepartmentID uuid.UUID  `json:"department_id"`
	CategoryID   uuid.UUID  `json:"category_id"`
	Type         TicketType `json:"ticket_type"`
	IncidentID   *uuid.UUID `json:"incident_id,omitempty"`

	UserID    uuid.UUID  `json:"user_id"`
	BrigadeID *uuid.UUID `json:"brigade_id,omitempty"`
	AssetID   *uuid.UUID `json:"asset_id,omitempty"`

	ExternalSystemID *uuid.UUID `json:"external_system_id,omitempty"`
	ExternalID       *string    `json:"external_id,omitempty"`

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

// TicketCategory описывает доменную модель.
type TicketCategory struct {
	ID          uuid.UUID `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TicketStatusHistory описывает доменную модель.
type TicketStatusHistory struct {
	ID       uuid.UUID `json:"id"`
	TicketID uuid.UUID `json:"ticket_id"`

	OldStatus *TicketStatus `json:"old_status,omitempty"`
	NewStatus TicketStatus  `json:"new_status"`

	ChangedBy *uuid.UUID `json:"changed_by,omitempty"`
	Comment   *string    `json:"comment,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// CreateTicketInput задаёт входные данные операции.
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
	AssetID   *uuid.UUID

	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// CreateTicketResult содержит результат операции.
type CreateTicketResult struct {
	Ticket *Ticket
}

// GetTicketInput задаёт входные данные операции.
type GetTicketInput struct {
	TicketID          uuid.UUID
	ActorUserID       *uuid.UUID
	ActorBrigadeID    *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// GetTicketResult содержит результат операции.
type GetTicketResult struct {
	Ticket *Ticket
}

// ListTicketsInput задаёт входные данные операции.
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

	ActorUserID       *uuid.UUID
	ActorBrigadeID    *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// ListTicketsResult содержит результат операции.
type ListTicketsResult struct {
	Tickets []*Ticket
	Total   int64
}

// UpdateTicketInput задаёт входные данные операции.
type UpdateTicketInput struct {
	TicketID uuid.UUID

	Title       *string
	Description *string
	CategoryID  *uuid.UUID
	Priority    *TicketPriority

	Address   *string
	Latitude  *float64
	Longitude *float64
	AssetID   *uuid.UUID

	UpdatedBy         *uuid.UUID
	ActorBrigadeID    *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// UpdateTicketResult содержит результат операции.
type UpdateTicketResult struct {
	Ticket *Ticket
}

// ChangeTicketStatusInput задаёт входные данные операции.
type ChangeTicketStatusInput struct {
	TicketID          uuid.UUID
	NewStatus         TicketStatus
	ChangedBy         uuid.UUID
	Comment           *string
	ActorBrigadeID    *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// ChangeTicketStatusResult содержит результат операции.
type ChangeTicketStatusResult struct {
	Ticket *Ticket
}

// AssignBrigadeInput задаёт входные данные операции.
type AssignBrigadeInput struct {
	TicketID          uuid.UUID
	BrigadeID         uuid.UUID
	AssignedBy        uuid.UUID
	Comment           *string
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// AssignBrigadeResult содержит результат операции.
type AssignBrigadeResult struct {
	Ticket *Ticket
}

// CancelTicketInput задаёт входные данные операции.
type CancelTicketInput struct {
	TicketID          uuid.UUID
	CanceledBy        uuid.UUID
	Reason            string
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// CancelTicketResult содержит результат операции.
type CancelTicketResult struct {
	Ticket *Ticket
}

// CompleteTicketInput задаёт входные данные операции.
type CompleteTicketInput struct {
	TicketID          uuid.UUID
	CompletedBy       uuid.UUID
	Comment           *string
	ActorBrigadeID    *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// CompleteTicketResult содержит результат операции.
type CompleteTicketResult struct {
	Ticket *Ticket
}

// GetTicketStatusHistoryInput задаёт входные данные операции.
type GetTicketStatusHistoryInput struct {
	TicketID          uuid.UUID
	Limit             int32
	Offset            int32
	ActorUserID       *uuid.UUID
	ActorBrigadeID    *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// GetTicketStatusHistoryResult содержит результат операции.
type GetTicketStatusHistoryResult struct {
	History []*TicketStatusHistory
	Total   int64
}

// CreateCategoryInput задаёт входные данные операции.
type CreateCategoryInput struct {
	Code        string
	Name        string
	Description *string
	ActorRoles  []string
}

// CreateCategoryResult содержит результат операции.
type CreateCategoryResult struct {
	Category *TicketCategory
}

// GetCategoryInput задаёт входные данные операции.
type GetCategoryInput struct {
	CategoryID uuid.UUID
}

// GetCategoryResult содержит результат операции.
type GetCategoryResult struct {
	Category *TicketCategory
}

// ListCategoriesInput задаёт входные данные операции.
type ListCategoriesInput struct {
	OnlyActive bool
	Limit      int32
	Offset     int32
}

// ListCategoriesResult содержит результат операции.
type ListCategoriesResult struct {
	Categories []*TicketCategory
	Total      int64
}

// UpdateCategoryInput задаёт входные данные операции.
type UpdateCategoryInput struct {
	CategoryID uuid.UUID

	Name        *string
	Description *string
	IsActive    *bool
	ActorRoles  []string
}

// UpdateCategoryResult содержит результат операции.
type UpdateCategoryResult struct {
	Category *TicketCategory
}

// DeleteCategoryInput задаёт входные данные операции.
type DeleteCategoryInput struct {
	CategoryID uuid.UUID
	ActorRoles []string
}

// DeleteCategoryResult содержит результат операции.
type DeleteCategoryResult struct {
	Category *TicketCategory
}
