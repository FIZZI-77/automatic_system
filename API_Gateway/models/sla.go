package models

// CreateSLARuleRequest содержит параметры API-запроса.
type CreateSLARuleRequest struct {
	Name                  string  `json:"name" binding:"required"`
	DepartmentID          *string `json:"department_id,omitempty"`
	CategoryID            *string `json:"category_id,omitempty"`
	Priority              *string `json:"priority,omitempty"`
	ResponseTimeSeconds   int64   `json:"response_time_seconds" binding:"required,gt=0"`
	ResolutionTimeSeconds int64   `json:"resolution_time_seconds" binding:"required,gt=0"`
	WarningPercent        int32   `json:"warning_percent" binding:"required,min=1,max=99"`
}

// UpdateSLARuleRequest содержит параметры API-запроса.
type UpdateSLARuleRequest struct {
	ID                    string  `json:"id" binding:"required,uuid"`
	Name                  *string `json:"name,omitempty"`
	DepartmentID          *string `json:"department_id,omitempty"`
	CategoryID            *string `json:"category_id,omitempty"`
	Priority              *string `json:"priority,omitempty"`
	ResponseTimeSeconds   *int64  `json:"response_time_seconds,omitempty"`
	ResolutionTimeSeconds *int64  `json:"resolution_time_seconds,omitempty"`
	WarningPercent        *int32  `json:"warning_percent,omitempty"`
	Active                *bool   `json:"active,omitempty"`
}

// SLAIDRequest содержит параметры API-запроса.
type SLAIDRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

// TicketIDRequest содержит параметры API-запроса.
type TicketIDRequest struct {
	TicketID string `json:"ticket_id" binding:"required,uuid"`
}

// ListSLARulesRequest содержит параметры API-запроса.
type ListSLARulesRequest struct {
	DepartmentID *string `json:"department_id,omitempty"`
	CategoryID   *string `json:"category_id,omitempty"`
	Priority     *string `json:"priority,omitempty"`
	Active       *bool   `json:"active,omitempty"`
	Limit        int32   `json:"limit,omitempty"`
	Offset       int32   `json:"offset,omitempty"`
}

// ListTicketSLAsRequest содержит параметры API-запроса.
type ListTicketSLAsRequest struct {
	DepartmentID *string `json:"department_id,omitempty"`
	Status       *string `json:"status,omitempty"`
	Breached     *bool   `json:"breached,omitempty"`
	Limit        int32   `json:"limit,omitempty"`
	Offset       int32   `json:"offset,omitempty"`
}
