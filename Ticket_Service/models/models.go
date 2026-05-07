package models

import "time"

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

type Ticket struct {
	ID           string `json:"id"`
	DepartmentID string `json:"department_id"`
	CategoryID   string `json:"category_id"`

	UserID    string  `json:"user_id"`
	BrigadeID *string `json:"brigade_id,omitempty"`

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
	ID          string    `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type TicketStatusHistory struct {
	ID       string `json:"id"`
	TicketID string `json:"ticket_id"`

	OldStatus TicketStatus `json:"old_status"`
	NewStatus TicketStatus `json:"new_status"`

	ChangedBy string `json:"changed_by"`
	Comment   string `json:"comment"`

	CreatedAt time.Time `json:"created_at"`
}

type CreateTicketInput struct {
	DepartmentID string
	CategoryID   string
	UserID       string

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
	TicketID string
}

type GetTicketResult struct {
	Ticket *Ticket
}

type ListTicketsInput struct {
	DepartmentID string
	UserID       string
	BrigadeID    string
	CategoryID   string

	Status   TicketStatus
	Priority TicketPriority

	CreatedFrom *time.Time
	CreatedTo   *time.Time

	Limit  int32
	Offset int32
}

type ListTicketsResult struct {
	Tickets []*Ticket
	Total   int64
}

type UpdateTicketInput struct {
	TicketID string

	Title       string
	Description string
	CategoryID  string
	Priority    TicketPriority

	Address string

	Latitude  *float64
	Longitude *float64

	UpdatedBy string
}

type UpdateTicketResult struct {
	Ticket *Ticket
}

type ChangeTicketStatusInput struct {
	TicketID  string
	NewStatus TicketStatus
	ChangedBy string
	Comment   string
}

type ChangeTicketStatusResult struct {
	Ticket *Ticket
}

type AssignBrigadeInput struct {
	TicketID   string
	BrigadeID  string
	AssignedBy string
	Comment    string
}

type AssignBrigadeResult struct {
	Ticket *Ticket
}

type CancelTicketInput struct {
	TicketID   string
	CanceledBy string
	Reason     string
}

type CancelTicketResult struct {
	Ticket *Ticket
}

type CompleteTicketInput struct {
	TicketID    string
	CompletedBy string
	Comment     string
}

type CompleteTicketResult struct {
	Ticket *Ticket
}

type GetTicketStatusHistoryInput struct {
	TicketID string
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
	Description string
}

type CreateCategoryResult struct {
	Category *TicketCategory
}

type GetCategoryInput struct {
	CategoryID string
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
	CategoryID  string
	Name        string
	Description string
	IsActive    bool
}

type UpdateCategoryResult struct {
	Category *TicketCategory
}

type DeleteCategoryInput struct {
	CategoryID string
}

type DeleteCategoryResult struct {
	Category *TicketCategory
}
