package models

import "time"

type TicketStatus string

const (
	TicketStatusNew        TicketStatus = "NEW"
	TicketStatusAssigned   TicketStatus = "ASSIGNED"
	TicketStatusInProgress TicketStatus = "IN_PROGRESS"
	TicketStatusDone       TicketStatus = "DONE"
	TicketStatusCanceled   TicketStatus = "CANCELED"
	TicketStatusArchived   TicketStatus = "ARCHIVED"
)

// IsValid сообщает, является ли статус одним из NEW, ASSIGNED, IN_PROGRESS, DONE или CANCELED.
// ARCHIVED и неизвестные значения недопустимы.
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

// IsValid сообщает, является ли приоритет одним из LOW, MEDIUM, HIGH или EMERGENCY.
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

// IsValid проверяет поле сортировки: created_at, updated_at, priority или status.
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

// IsValid проверяет направление сортировки: asc или desc с учётом регистра.
func (s SortOrder) IsValid() bool {
	switch s {
	case SortOrderAsc, SortOrderDesc:
		return true
	default:
		return false
	}
}

type TicketCategory struct {
	ID            string `json:"id"`
	Code          string `json:"code"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	IsActive      bool   `json:"is_active"`
	CreatedAtUnix int64  `json:"created_at"`
	UpdatedAtUnix int64  `json:"updated_at"`
}

type Ticket struct {
	ID               string  `json:"id"`
	DepartmentID     string  `json:"department_id"`
	CategoryID       string  `json:"category_id"`
	UserID           string  `json:"user_id"`
	BrigadeID        string  `json:"brigade_id,omitempty"`
	Title            string  `json:"title"`
	Description      string  `json:"description"`
	Status           string  `json:"status"`
	Priority         string  `json:"priority"`
	Address          string  `json:"address"`
	Latitude         float64 `json:"latitude"`
	Longitude        float64 `json:"longitude"`
	CreatedAtUnix    int64   `json:"created_at"`
	UpdatedAtUnix    int64   `json:"updated_at"`
	AssignedAtUnix   int64   `json:"assigned_at,omitempty"`
	CompletedAtUnix  int64   `json:"completed_at,omitempty"`
	CanceledAtUnix   int64   `json:"canceled_at,omitempty"`
	TicketType       string  `json:"ticket_type"`
	IncidentID       string  `json:"incident_id,omitempty"`
	ExternalSystemID string  `json:"external_system_id,omitempty"`
	ExternalID       string  `json:"external_id,omitempty"`
}

type CreateRequestRequest struct {
	DepartmentID string  `json:"department_id" binding:"required,uuid"`
	CategoryID   string  `json:"category_id" binding:"required,uuid"`
	Title        string  `json:"title" binding:"required,max=255"`
	Description  string  `json:"description" binding:"required,max=3000"`
	Priority     string  `json:"priority" binding:"required,oneof=LOW MEDIUM HIGH EMERGENCY"`
	Address      string  `json:"address" binding:"required,max=500"`
	Latitude     float64 `json:"latitude" binding:"latitude"`
	Longitude    float64 `json:"longitude" binding:"longitude"`
	AssetID      *string `json:"asset_id,omitempty" binding:"omitempty,uuid"`
}

type CreateRequestResponse struct {
	Request          *Ticket `json:"request"`
	Incident         *Ticket `json:"incident"`
	DuplicateMatched bool    `json:"duplicate_matched"`
}

type AttachRequestRequest struct {
	IncidentID string `json:"incident_id" binding:"required,uuid"`
	RequestID  string `json:"request_id" binding:"required,uuid"`
	Reason     string `json:"reason" binding:"required,max=1000"`
}

type DetachRequestRequest struct {
	RequestID string `json:"request_id" binding:"required,uuid"`
	Reason    string `json:"reason" binding:"required,max=1000"`
}

type ListIncidentRequestsRequest struct {
	IncidentID string `json:"incident_id" binding:"required,uuid"`
	Limit      *int32 `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset     *int32 `json:"offset,omitempty" binding:"omitempty,min=0"`
}

type ListIncidentRequestsResponse struct {
	Requests          []*Ticket `json:"requests"`
	Total             int64     `json:"total"`
	Completed         int64     `json:"completed"`
	DepartmentCount   int       `json:"department_count"`
	IsComposite       bool      `json:"is_composite"`
	AllPartsCompleted bool      `json:"all_parts_completed"`
}

type RegisterTicketIntegrationRequest struct {
	Name                string  `json:"name" binding:"required,max=255"`
	ClientID            string  `json:"client_id" binding:"required,min=3,max=100"`
	AllowedDepartmentID *string `json:"allowed_department_id,omitempty" binding:"omitempty,uuid"`
}

type TicketIntegration struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	ClientID            string    `json:"client_id"`
	SecretPrefix        string    `json:"secret_prefix"`
	AllowedDepartmentID string    `json:"allowed_department_id,omitempty"`
	IsActive            bool      `json:"is_active"`
	CreatedBy           string    `json:"created_by"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	LastUsedAt          time.Time `json:"last_used_at,omitempty"`
}

type RegisterTicketIntegrationResponse struct {
	Integration *TicketIntegration `json:"integration"`
	Secret      string             `json:"secret"`
}

type ListTicketIntegrationsRequest struct {
	Limit  *int32 `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset *int32 `json:"offset,omitempty" binding:"omitempty,min=0"`
}

type ListTicketIntegrationsResponse struct {
	Integrations []*TicketIntegration `json:"integrations"`
	Total        int64                `json:"total"`
}

type SetTicketIntegrationActiveRequest struct {
	IntegrationID string `json:"integration_id" binding:"required,uuid"`
	IsActive      *bool  `json:"is_active" binding:"required"`
}

type RotateTicketIntegrationSecretRequest struct {
	IntegrationID string `json:"integration_id" binding:"required,uuid"`
}

type CreateExternalTicketRequest struct {
	ClientID     string  `json:"client_id" binding:"required"`
	Secret       string  `json:"secret" binding:"required"`
	ExternalID   string  `json:"external_id" binding:"required,max=255"`
	DepartmentID string  `json:"department_id" binding:"required,uuid"`
	CategoryID   string  `json:"category_id" binding:"required,uuid"`
	UserID       string  `json:"user_id" binding:"required,uuid"`
	Title        string  `json:"title" binding:"required,max=255"`
	Description  string  `json:"description" binding:"required,max=3000"`
	Priority     string  `json:"priority" binding:"required,oneof=LOW MEDIUM HIGH EMERGENCY"`
	Address      string  `json:"address" binding:"required,max=500"`
	Latitude     float64 `json:"latitude" binding:"latitude"`
	Longitude    float64 `json:"longitude" binding:"longitude"`
	AssetID      *string `json:"asset_id,omitempty" binding:"omitempty,uuid"`
}

type TicketStatusHistory struct {
	ID            string `json:"id"`
	TicketID      string `json:"ticket_id"`
	OldStatus     string `json:"old_status,omitempty"`
	NewStatus     string `json:"new_status"`
	ChangedBy     string `json:"changed_by,omitempty"`
	Comment       string `json:"comment,omitempty"`
	CreatedAtUnix int64  `json:"created_at"`
}

type CreateTicketRequest struct {
	DepartmentID string   `json:"department_id" binding:"required,uuid"`
	CategoryID   string   `json:"category_id" binding:"required,uuid"`
	UserID       string   `json:"user_id,omitempty" binding:"omitempty,uuid"`
	Title        string   `json:"title" binding:"required"`
	Description  string   `json:"description" binding:"required"`
	Priority     string   `json:"priority" binding:"required,oneof=LOW MEDIUM HIGH EMERGENCY"`
	Address      string   `json:"address" binding:"required"`
	Latitude     *float64 `json:"latitude" binding:"required,latitude"`
	Longitude    *float64 `json:"longitude" binding:"required,longitude"`
	AssetID      *string  `json:"asset_id,omitempty" binding:"omitempty,uuid"`
}

type CreateTicketResponse struct {
	Ticket *Ticket `json:"ticket"`
}

type GetTicketRequest struct {
	TicketID string `json:"ticket_id" binding:"required,uuid"`
}

type GetTicketResponse struct {
	Ticket *Ticket `json:"ticket"`
}

type ListTicketRequest struct {
	DepartmentID *string `json:"department_id,omitempty" binding:"omitempty,uuid"`
	CategoryID   *string `json:"category_id,omitempty" binding:"omitempty,uuid"`
	Status       *string `json:"status,omitempty" binding:"omitempty,oneof=NEW ASSIGNED IN_PROGRESS DONE CANCELED"`
	UserID       *string `json:"user_id,omitempty" binding:"omitempty,uuid"`
	BrigadeID    *string `json:"brigade_id,omitempty" binding:"omitempty,uuid"`
	Priority     *string `json:"priority,omitempty" binding:"omitempty,oneof=LOW MEDIUM HIGH EMERGENCY"`
	Limit        *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset       *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
	SortBy       *string `json:"sort_by,omitempty" binding:"omitempty,oneof=created_at updated_at priority status"`
	SortOrder    *string `json:"sort_order,omitempty" binding:"omitempty,oneof=asc desc"`
	CreatedFrom  *string `json:"created_from,omitempty" binding:"omitempty,datetime=2006-01-02T15:04:05Z"`
	CreatedTo    *string `json:"created_to,omitempty" binding:"omitempty,datetime=2006-01-02T15:04:05Z"`
}

type ListTicketResponse struct {
	Tickets []*Ticket `json:"tickets"`
	Total   int64     `json:"total"`
}

type UpdateTicketRequest struct {
	TicketID    string   `json:"ticket_id" binding:"required,uuid"`
	Title       *string  `json:"title" binding:"omitempty"`
	Description *string  `json:"description" binding:"omitempty"`
	CategoryID  *string  `json:"category_id,omitempty" binding:"omitempty,uuid"`
	Priority    *string  `json:"priority,omitempty" binding:"omitempty,oneof=LOW MEDIUM HIGH EMERGENCY"`
	Address     *string  `json:"address,omitempty" binding:"omitempty"`
	Latitude    *float64 `json:"latitude,omitempty" binding:"omitempty,latitude"`
	Longitude   *float64 `json:"longitude,omitempty" binding:"omitempty,longitude"`
	UpdatedBy   *string  `json:"updated_by,omitempty" binding:"omitempty,uuid"`
	AssetID     *string  `json:"asset_id,omitempty" binding:"omitempty,uuid"`
}

type UpdateTicketResponse struct {
	Ticket *Ticket `json:"ticket"`
}

type ChangeTicketStatusRequest struct {
	TicketID  string `json:"ticket_id" binding:"required,uuid"`
	NewStatus string `json:"new_status" binding:"required,oneof=new assigned in_progress done canceled"`
	ChangedBy string `json:"changed_by,omitempty" binding:"omitempty,uuid"`
	Comment   string `json:"comment" binding:"omitempty"`
}

type ChangeTicketStatusResponse struct {
	Ticket *Ticket `json:"ticket"`
}

type AssignBrigadeRequest struct {
	TicketID   string `json:"ticket_id" binding:"required,uuid"`
	BrigadeID  string `json:"brigade_id" binding:"required,uuid"`
	AssignedBy string `json:"assigned_by,omitempty" binding:"omitempty,uuid"`
	Comment    string `json:"comment" binding:"omitempty"`
}

type AssignBrigadeResponse struct {
	Ticket *Ticket `json:"ticket"`
}

type CancelTicketRequest struct {
	TicketID   string `json:"ticket_id" binding:"required,uuid"`
	CanceledBy string `json:"canceled_by,omitempty" binding:"omitempty,uuid"`
	Reason     string `json:"reason" binding:"required"`
}

type CancelTicketResponse struct {
	Ticket *Ticket `json:"ticket"`
}

type CompleteTicketRequest struct {
	TicketID    string  `json:"ticket_id" binding:"required,uuid"`
	CompletedBy string  `json:"completed_by,omitempty" binding:"omitempty,uuid"`
	Comment     *string `json:"comment" binding:"omitempty"`
}

type CompleteTicketResponse struct {
	Ticket *Ticket `json:"ticket"`
}

type GetTicketStatusHistoryRequest struct {
	TicketID string `json:"ticket_id" binding:"required,uuid"`
	Limit    *int32 `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset   *int32 `json:"offset,omitempty" binding:"omitempty,min=0"`
}

type GetTicketStatusHistoryResponse struct {
	History []*TicketStatusHistory `json:"history"`
	Total   int64                  `json:"total"`
}

type WorkReport struct {
	ID               string    `json:"id"`
	TicketID         string    `json:"ticket_id"`
	AuthorUserID     string    `json:"author_user_id"`
	Description      string    `json:"description"`
	FileIDs          []string  `json:"file_ids"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	CompletionStatus string    `json:"completion_status"`
	CompletionFileID string    `json:"completion_file_id,omitempty"`
	CompletionError  string    `json:"completion_error,omitempty"`
}
type CreateWorkReportRequest struct {
	TicketID    string   `json:"ticket_id" binding:"required,uuid"`
	Description string   `json:"description" binding:"required,max=4000"`
	FileIDs     []string `json:"file_ids" binding:"max=20,dive,uuid"`
}
type ListWorkReportsRequest struct {
	TicketID string `json:"ticket_id" binding:"required,uuid"`
}

type CreateCategoryRequest struct {
	Code        string  `json:"code" binding:"required"`
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description" binding:"omitempty"`
}

type CreateCategoryResponse struct {
	Category *TicketCategory `json:"category"`
}

type GetCategoryRequest struct {
	CategoryID string `json:"category_id" binding:"required,uuid"`
}

type GetCategoryResponse struct {
	Category *TicketCategory `json:"category"`
}

type ListCategoriesRequest struct {
	OnlyActive *bool  `json:"only_active,omitempty" binding:"omitempty"`
	Limit      *int32 `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset     *int32 `json:"offset,omitempty" binding:"omitempty,min=0"`
}

type UpdateCategoryRequest struct {
	CategoryID  string  `json:"category_id" binding:"required,uuid"`
	Name        *string `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	Description *string `json:"description,omitempty" binding:"omitempty,max=500"`
	IsActive    *bool   `json:"is_active,omitempty" binding:"omitempty"`
}

type DeleteCategoryRequest struct {
	CategoryID string `json:"category_id" binding:"required,uuid"`
}

type ListCategoriesResponse struct {
	Categories []*TicketCategory `json:"categories"`
	Total      int64             `json:"total"`
}

type DeleteCategoryResponse struct {
	Category *TicketCategory `json:"category"`
}

type UpdateCategoryResponse struct {
	Category *TicketCategory `json:"category"`
}
