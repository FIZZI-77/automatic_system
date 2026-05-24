package models

type TicketCategory struct {
	CategoryID    string `json:"category_id"`
	CategoryCode  string `json:"category_code"`
	CategoryName  string `json:"category_name"`
	Description   string `json:"description"`
	IsActive      bool   `json:"is_active"`
	CreatedAtUnix int64  `json:"created_at"`
	UpdatedAtUnix int64  `json:"updated_at"`
}
type Ticket struct {
	TicketID     string `json:"ticket_id"`
	DepartmentID string `json:"department_id"`
	CategoryID   string `json:"category_id"`
	UserID       string `json:"user_id"`
	BrigadeID    string `json:"brigade_id"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	TicketStatus string `json:"ticket_status"`
}

type TicketStatusHistory struct {
	ID            string `json:"id"`
	TicketID      string `json:"ticket_id"`
	OldStatus     string `json:"old_status"`
	NewStatus     string `json:"new_status"`
	ChangeBy      string `json:"change_by"`
	Comment       string `json:"comment"`
	CreatedAtUnix int64  `json:"created_at"`
}

type CreateTicketRequest struct {
	DepartmentID   string  `json:"department_id" binding:"required,uuid"`
	CategoryID     string  `json:"category_id" binding:"required,uuid"`
	UserID         string  `json:"user_id" binding:"required,uuid"`
	Title          string  `json:"title" binding:"required"`
	Description    string  `json:"description" binding:"required"`
	TicketPriority string  `json:"ticket_prior" binding:"required,oneof=low medium high emergency"`
	Address        string  `json:"address" binding:"required"`
	Latitude       float64 `json:"latitude" binding:"required"`
	Longitude      float64 `json:"longitude" binding:"required"`
}

type CreateTicketResponse struct {
	*Ticket
}

type GetTicketRequest struct {
	TicketID string `json:"ticket_id" binding:"required,uuid"`
}

type GetTicketResponse struct {
	*Ticket
}

type ListTicketRequest struct {
	DepartmentID *string `json:"department_id,omitempty" binding:"omitempty,uuid"`
	CategoryID   *string `json:"category_id,omitempty" binding:"omitempty,uuid"`
	TicketStatus *string `json:"status,omitempty" binding:"omitempty,oneof=new assigned in_progress done canceled"`
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
	Latitude    *float64 `json:"latitude" binding:"omitempty"`
	Longitude   *float64 `json:"longitude" binding:"omitempty"`
}

type UpdateTicketResponse struct {
	*Ticket
}

type ChangeTicketStatusRequest struct {
	TicketID  string `json:"ticket_id" binding:"required,uuid"`
	NewStatus string `json:"new_status" binding:"required,oneof=new assigned in_progress done canceled"`
	ChangeBy  string `json:"change_by" binding:"required,uuid"`
	Comment   string `json:"comment" binding:"omitempty"`
}

type ChangeTicketStatusResponse struct {
	*Ticket
}

type AssignBrigadeRequest struct {
	TicketID   string  `json:"ticket_id" binding:"required,uuid"`
	BrigadeID  string  `json:"brigade_id" binding:"required,uuid"`
	AssignedBy *string `json:"assigned_by,omitempty" binding:"omitempty,uuid"`
	Comment    string  `json:"comment" binding:"omitempty"`
}

type AssignBrigadeResponse struct {
	*Ticket
}

type CancelTicketRequest struct {
	TicketID string  `json:"ticket_id" binding:"required,uuid"`
	CancelBy string  `json:"cancel_by" binding:"required,uuid"`
	Reason   *string `json:"reason" binding:"omitempty"`
}

type CancelTicketResponse struct {
	*Ticket
}

type CompleteTicketRequest struct {
	TicketID    string  `json:"ticket_id" binding:"required,uuid"`
	CompletedBy string  `json:"completed_by" binding:"required,uuid"`
	Comment     *string `json:"comment" binding:"omitempty"`
}

type CompleteTicketResponse struct {
	*Ticket
}

type GetTicketStatusHistoryRequest struct {
	TicketID string `json:"ticket_id" binding:"required,uuid"`
	Limit    *int32 `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset   *int32 `json:"offset,omitempty" binding:"omitempty,min=0"`
}

type GetTicketHistoryResponse struct {
	Tickets []*Ticket `json:"tickets"`
	Total   int64     `json:"total"`
}

type CreateCategoryRequest struct {
	Code        string  `json:"code" binding:"required"`
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description" binding:"omitempty"`
}

type CreateCategoryResponse struct {
	*TicketCategory
}

type GetCategoryRequest struct {
	CategoryID string `json:"category_id" binding:"required,uuid"`
}

type GetCategoryResponse struct {
	*TicketCategory
}

type ListCategoriesRequest struct {
	OnlyActive *bool  `json:"only_active,omitempty" binding:"omitempty"`
	Limit      *int32 `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset     *int32 `json:"offset,omitempty" binding:"omitempty,min=0"`
}

type UpdateCategoryRequest struct {
	CategoryID  string  `json:"category_id" binding:"required,uuid4"`
	Name        *string `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	Description *string `json:"description,omitempty" binding:"omitempty,max=500"`
	IsActive    *bool   `json:"is_active,omitempty" binding:"omitempty"`
}

type DeleteCategoryRequest struct {
	CategoryID string `json:"category_id" binding:"required,uuid4"`
}

type CategoryResponse struct {
	ID            string `json:"id"`
	Code          string `json:"code"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	IsActive      bool   `json:"is_active"`
	CreatedAtUnix int64  `json:"created_at"`
	UpdatedAtUnix int64  `json:"updated_at"`
}

type ListCategoriesResponse struct {
	Categories []*TicketCategory `json:"categories"`
	Total      int64             `json:"total"`
}

type DeleteCategoryResponse struct {
	*TicketCategory
}

type UpdateCategoryResponse struct {
	*TicketCategory
}
