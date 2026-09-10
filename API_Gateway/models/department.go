package models

type DepartmentStatus string

const (
	DepartmentStatusActive   DepartmentStatus = "ACTIVE"
	DepartmentStatusInactive DepartmentStatus = "INACTIVE"
	DepartmentStatusArchived DepartmentStatus = "ARCHIVED"
)

type DepartmentSortBy string

const (
	DepartmentSortByCreatedAt DepartmentSortBy = "created_at"
	DepartmentSortByUpdatedAt DepartmentSortBy = "updated_at"
	DepartmentSortByName      DepartmentSortBy = "name"
	DepartmentSortByStatus    DepartmentSortBy = "status"
)

type Department struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Status        string `json:"status"`
	CreatedAtUnix int64  `json:"created_at"`
	UpdatedAtUnix int64  `json:"updated_at"`
}

type CreateDepartmentRequest struct {
	Name        string `json:"name" binding:"required,min=2,max=255"`
	Description string `json:"description" binding:"omitempty,max=1000"`
}

type CreateDepartmentResponse struct {
	Department *Department `json:"department"`
}

type GetDepartmentByIDRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

type GetDepartmentByIDResponse struct {
	Department *Department `json:"department"`
}

type ListDepartmentsRequest struct {
	Status      *string `json:"status,omitempty" binding:"omitempty,oneof=active inactive archived"`
	CreatedFrom *string `json:"created_from,omitempty" binding:"omitempty,datetime=2006-01-02T15:04:05Z"`
	CreatedTo   *string `json:"created_to,omitempty" binding:"omitempty,datetime=2006-01-02T15:04:05Z"`
	Limit       *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset      *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
	SortBy      *string `json:"sort_by,omitempty" binding:"omitempty,oneof=created_at updated_at name status"`
	SortOrder   *string `json:"sort_order,omitempty" binding:"omitempty,oneof=asc desc"`
}

type ListDepartmentsResponse struct {
	Departments []*Department `json:"departments"`
	Total       int64         `json:"total"`
}

type UpdateDepartmentRequest struct {
	ID          string  `json:"id" binding:"required,uuid"`
	Name        *string `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	Description *string `json:"description,omitempty" binding:"omitempty,max=1000"`
	Status      *string `json:"status,omitempty" binding:"omitempty,oneof=active inactive archived"`
}

type UpdateDepartmentResponse struct {
	Department *Department `json:"department"`
}

type DeleteDepartmentRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

type DeleteDepartmentResponse struct {
	Department *Department `json:"department"`
}
