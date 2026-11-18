package models

import (
	"time"

	"github.com/google/uuid"
)

// DepartmentStatus задаёт допустимое состояние модели.
type DepartmentStatus string

const (
	DepartmentStatusActive   DepartmentStatus = "ACTIVE"
	DepartmentStatusInactive DepartmentStatus = "INACTIVE"
	DepartmentStatusArchived DepartmentStatus = "ARCHIVED"
)

// IsValid сообщает, является ли статус одним из ACTIVE, INACTIVE или ARCHIVED.
func (s DepartmentStatus) IsValid() bool {
	switch s {
	case DepartmentStatusActive, DepartmentStatusInactive, DepartmentStatusArchived:
		return true
	default:
		return false
	}
}

// DepartmentSortBy задаёт поле сортировки.
type DepartmentSortBy string

const (
	DepartmentSortByCreatedAt DepartmentSortBy = "created_at"
	DepartmentSortByUpdatedAt DepartmentSortBy = "updated_at"
	DepartmentSortByName      DepartmentSortBy = "name"
	DepartmentSortByStatus    DepartmentSortBy = "status"
)

// IsValid проверяет поле сортировки: created_at, updated_at, name или status.
func (s DepartmentSortBy) IsValid() bool {
	switch s {
	case DepartmentSortByCreatedAt, DepartmentSortByUpdatedAt, DepartmentSortByName, DepartmentSortByStatus:
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

// IsValid проверяет направление сортировки: asc или desc с учётом регистра.
func (s SortOrder) IsValid() bool {
	switch s {
	case SortOrderAsc, SortOrderDesc:
		return true
	default:
		return false
	}
}

// Department описывает ведомство и его текущее состояние.
type Department struct {
	ID          uuid.UUID
	Name        string
	Description string
	Status      DepartmentStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// CreateDepartmentInput задаёт входные данные операции.
type CreateDepartmentInput struct {
	Name        string
	Description string
	ActorRoles  []string
}

// CreateDepartmentResult содержит результат операции.
type CreateDepartmentResult struct {
	Department *Department
}

// GetDepartmentByIDInput задаёт входные данные операции.
type GetDepartmentByIDInput struct {
	ID uuid.UUID
}

// GetDepartmentByIDResult содержит результат операции.
type GetDepartmentByIDResult struct {
	Department *Department
}

// ListDepartmentsInput задаёт входные данные операции.
type ListDepartmentsInput struct {
	Status      *DepartmentStatus
	CreatedFrom *time.Time
	CreatedTo   *time.Time
	SortBy      DepartmentSortBy
	SortOrder   SortOrder
	Limit       int32
	Offset      int32
}

// ListDepartmentsResult содержит результат операции.
type ListDepartmentsResult struct {
	Departments []*Department
	Total       int64
}

// UpdateDepartmentInput задаёт входные данные операции.
type UpdateDepartmentInput struct {
	ID          uuid.UUID
	Name        *string
	Description *string
	Status      *DepartmentStatus
	ActorRoles  []string
}

// UpdateDepartmentResult содержит результат операции.
type UpdateDepartmentResult struct {
	Department *Department
}

// DeleteDepartmentInput задаёт входные данные операции.
type DeleteDepartmentInput struct {
	ID         uuid.UUID
	ActorRoles []string
}

// DeleteDepartmentResult содержит результат операции.
type DeleteDepartmentResult struct {
	Department *Department
}
