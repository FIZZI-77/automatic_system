package models

import (
	"time"

	"github.com/google/uuid"
)

type DepartmentStatus string

const (
	DepartmentStatusActive   DepartmentStatus = "ACTIVE"
	DepartmentStatusInactive DepartmentStatus = "INACTIVE"
	DepartmentStatusArchived DepartmentStatus = "ARCHIVED"
)

func (s DepartmentStatus) IsValid() bool {
	switch s {
	case DepartmentStatusActive, DepartmentStatusInactive, DepartmentStatusArchived:
		return true
	default:
		return false
	}
}

type DepartmentSortBy string

const (
	DepartmentSortByCreatedAt DepartmentSortBy = "created_at"
	DepartmentSortByUpdatedAt DepartmentSortBy = "updated_at"
	DepartmentSortByName      DepartmentSortBy = "name"
	DepartmentSortByStatus    DepartmentSortBy = "status"
)

func (s DepartmentSortBy) IsValid() bool {
	switch s {
	case DepartmentSortByCreatedAt, DepartmentSortByUpdatedAt, DepartmentSortByName, DepartmentSortByStatus:
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

type Department struct {
	ID          uuid.UUID
	Name        string
	Description string
	Status      DepartmentStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type CreateDepartmentInput struct {
	Name        string
	Description string
	ActorRoles  []string
}

type CreateDepartmentResult struct {
	Department *Department
}

type GetDepartmentByIDInput struct {
	ID uuid.UUID
}

type GetDepartmentByIDResult struct {
	Department *Department
}

type ListDepartmentsInput struct {
	Status      *DepartmentStatus
	CreatedFrom *time.Time
	CreatedTo   *time.Time
	SortBy      DepartmentSortBy
	SortOrder   SortOrder
	Limit       int32
	Offset      int32
}

type ListDepartmentsResult struct {
	Departments []*Department
	Total       int64
}

type UpdateDepartmentInput struct {
	ID          uuid.UUID
	Name        *string
	Description *string
	Status      *DepartmentStatus
	ActorRoles  []string
}

type UpdateDepartmentResult struct {
	Department *Department
}

type DeleteDepartmentInput struct {
	ID         uuid.UUID
	ActorRoles []string
}

type DeleteDepartmentResult struct {
	Department *Department
}
