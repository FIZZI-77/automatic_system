package models

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
	ID              string  `json:"id"`
	DepartmentID    string  `json:"department_id"`
	CategoryID      string  `json:"category_id"`
	UserID          string  `json:"user_id"`
	BrigadeID       string  `json:"brigade_id,omitempty"`
	Title           string  `json:"title"`
	Description     string  `json:"description"`
	Status          string  `json:"status"`
	Priority        string  `json:"priority"`
	Address         string  `json:"address"`
	Latitude        float64 `json:"latitude"`
	Longitude       float64 `json:"longitude"`
	CreatedAtUnix   int64   `json:"created_at"`
	UpdatedAtUnix   int64   `json:"updated_at"`
	AssignedAtUnix  int64   `json:"assigned_at,omitempty"`
	CompletedAtUnix int64   `json:"completed_at,omitempty"`
	CanceledAtUnix  int64   `json:"canceled_at,omitempty"`
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
	UserID       string   `json:"user_id" binding:"required,uuid"`
	Title        string   `json:"title" binding:"required"`
	Description  string   `json:"description" binding:"required"`
	Priority     string   `json:"priority" binding:"required,oneof=low medium high emergency"`
	Address      string   `json:"address" binding:"required"`
	Latitude     *float64 `json:"latitude" binding:"required,latitude"`
	Longitude    *float64 `json:"longitude" binding:"required,longitude"`
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
	Status       *string `json:"status,omitempty" binding:"omitempty,oneof=new assigned in_progress done canceled"`
	UserID       *string `json:"user_id,omitempty" binding:"omitempty,uuid"`
	BrigadeID    *string `json:"brigade_id,omitempty" binding:"omitempty,uuid"`
	Priority     *string `json:"priority,omitempty" binding:"omitempty,oneof=low medium high emergency"`
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
	Priority    *string  `json:"priority,omitempty" binding:"omitempty,oneof=low medium high emergency"`
	Address     *string  `json:"address,omitempty" binding:"omitempty"`
	Latitude    *float64 `json:"latitude,omitempty" binding:"omitempty,latitude"`
	Longitude   *float64 `json:"longitude,omitempty" binding:"omitempty,longitude"`
	UpdatedBy   *string  `json:"updated_by,omitempty" binding:"omitempty,uuid"`
}

type UpdateTicketResponse struct {
	Ticket *Ticket `json:"ticket"`
}

type ChangeTicketStatusRequest struct {
	TicketID  string `json:"ticket_id" binding:"required,uuid"`
	NewStatus string `json:"new_status" binding:"required,oneof=new assigned in_progress done canceled"`
	ChangedBy string `json:"changed_by" binding:"required,uuid"`
	Comment   string `json:"comment" binding:"omitempty"`
}

type ChangeTicketStatusResponse struct {
	Ticket *Ticket `json:"ticket"`
}

type AssignBrigadeRequest struct {
	TicketID   string `json:"ticket_id" binding:"required,uuid"`
	BrigadeID  string `json:"brigade_id" binding:"required,uuid"`
	AssignedBy string `json:"assigned_by" binding:"required,uuid"`
	Comment    string `json:"comment" binding:"omitempty"`
}

type AssignBrigadeResponse struct {
	Ticket *Ticket `json:"ticket"`
}

type CancelTicketRequest struct {
	TicketID   string `json:"ticket_id" binding:"required,uuid"`
	CanceledBy string `json:"canceled_by" binding:"required,uuid"`
	Reason     string `json:"reason" binding:"required"`
}

type CancelTicketResponse struct {
	Ticket *Ticket `json:"ticket"`
}

type CompleteTicketRequest struct {
	TicketID    string  `json:"ticket_id" binding:"required,uuid"`
	CompletedBy string  `json:"completed_by" binding:"required,uuid"`
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
