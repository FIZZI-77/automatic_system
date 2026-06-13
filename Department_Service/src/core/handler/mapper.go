package handler

import (
	"department/models"
	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

func ToProtoStatus(status models.DepartmentStatus) departmentv1.DepartmentStatus {
	switch status {
	case models.DepartmentStatusActive:
		return departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ACTIVE
	case models.DepartmentStatusInactive:
		return departmentv1.DepartmentStatus_DEPARTMENT_STATUS_INACTIVE
	case models.DepartmentStatusArchived:
		return departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ARCHIVED
	default:
		return departmentv1.DepartmentStatus_DEPARTMENT_STATUS_UNSPECIFIED
	}
}

func FromProtoStatus(status departmentv1.DepartmentStatus) models.DepartmentStatus {
	switch status {
	case departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ACTIVE:
		return models.DepartmentStatusActive
	case departmentv1.DepartmentStatus_DEPARTMENT_STATUS_INACTIVE:
		return models.DepartmentStatusInactive
	case departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ARCHIVED:
		return models.DepartmentStatusArchived
	default:
		return ""
	}
}

func FromProtoSortBy(sortBy departmentv1.DepartmentSortBy) models.DepartmentSortBy {
	switch sortBy {
	case departmentv1.DepartmentSortBy_DEPARTMENT_SORT_BY_CREATED_AT:
		return models.DepartmentSortByCreatedAt
	case departmentv1.DepartmentSortBy_DEPARTMENT_SORT_BY_UPDATED_AT:
		return models.DepartmentSortByUpdatedAt
	case departmentv1.DepartmentSortBy_DEPARTMENT_SORT_BY_NAME:
		return models.DepartmentSortByName
	case departmentv1.DepartmentSortBy_DEPARTMENT_SORT_BY_STATUS:
		return models.DepartmentSortByStatus
	default:
		return ""
	}
}

func FromProtoSortOrder(order departmentv1.SortOrder) models.SortOrder {
	switch order {
	case departmentv1.SortOrder_SORT_ORDER_ASC:
		return models.SortOrderAsc
	case departmentv1.SortOrder_SORT_ORDER_DESC:
		return models.SortOrderDesc
	default:
		return ""
	}
}

func ToProtoTimestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func FromProtoTimestamp(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}

func ToProtoDepartment(department *models.Department) *departmentv1.Department {
	if department == nil {
		return nil
	}
	return &departmentv1.Department{
		Id:          department.ID.String(),
		Name:        department.Name,
		Description: department.Description,
		Status:      ToProtoStatus(department.Status),
		CreatedAt:   ToProtoTimestamp(department.CreatedAt),
		UpdatedAt:   ToProtoTimestamp(department.UpdatedAt),
	}
}
