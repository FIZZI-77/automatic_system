package models

// DepartmentStatus задаёт допустимое состояние модели.
type DepartmentStatus string

const (
	DepartmentStatusActive   DepartmentStatus = "ACTIVE"
	DepartmentStatusInactive DepartmentStatus = "INACTIVE"
	DepartmentStatusArchived DepartmentStatus = "ARCHIVED"
)

// DepartmentSortBy задаёт поле сортировки.
type DepartmentSortBy string

const (
	DepartmentSortByCreatedAt DepartmentSortBy = "created_at"
	DepartmentSortByUpdatedAt DepartmentSortBy = "updated_at"
	DepartmentSortByName      DepartmentSortBy = "name"
	DepartmentSortByStatus    DepartmentSortBy = "status"
)

// Department описывает ведомство и его текущее состояние.
type Department struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Status        string `json:"status"`
	CreatedAtUnix int64  `json:"created_at"`
	UpdatedAtUnix int64  `json:"updated_at"`
}

// CreateDepartmentRequest содержит параметры API-запроса.
type CreateDepartmentRequest struct {
	Name        string `json:"name" binding:"required,min=2,max=255"`
	Description string `json:"description" binding:"omitempty,max=1000"`
}

// CreateDepartmentResponse содержит данные API-ответа.
type CreateDepartmentResponse struct {
	Department *Department `json:"department"`
}

// GetDepartmentByIDRequest содержит параметры API-запроса.
type GetDepartmentByIDRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

// GetDepartmentByIDResponse содержит данные API-ответа.
type GetDepartmentByIDResponse struct {
	Department *Department `json:"department"`
}

// ListDepartmentsRequest содержит параметры API-запроса.
type ListDepartmentsRequest struct {
	Status      *string `json:"status,omitempty" binding:"omitempty,oneof=active inactive archived"`
	CreatedFrom *string `json:"created_from,omitempty" binding:"omitempty,datetime=2006-01-02T15:04:05Z"`
	CreatedTo   *string `json:"created_to,omitempty" binding:"omitempty,datetime=2006-01-02T15:04:05Z"`
	Limit       *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset      *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
	SortBy      *string `json:"sort_by,omitempty" binding:"omitempty,oneof=created_at updated_at name status"`
	SortOrder   *string `json:"sort_order,omitempty" binding:"omitempty,oneof=asc desc"`
}

// ListDepartmentsResponse содержит данные API-ответа.
type ListDepartmentsResponse struct {
	Departments []*Department `json:"departments"`
	Total       int64         `json:"total"`
}

// UpdateDepartmentRequest содержит параметры API-запроса.
type UpdateDepartmentRequest struct {
	ID          string  `json:"id" binding:"required,uuid"`
	Name        *string `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	Description *string `json:"description,omitempty" binding:"omitempty,max=1000"`
	Status      *string `json:"status,omitempty" binding:"omitempty,oneof=active inactive archived"`
}

// UpdateDepartmentResponse содержит данные API-ответа.
type UpdateDepartmentResponse struct {
	Department *Department `json:"department"`
}

// DeleteDepartmentRequest содержит параметры API-запроса.
type DeleteDepartmentRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

// DeleteDepartmentResponse содержит данные API-ответа.
type DeleteDepartmentResponse struct {
	Department *Department `json:"department"`
}
