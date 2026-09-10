package handlers

import (
	"gateway/models"
	"strings"

	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
)

func ToProtoDepartmentStatus(status string) departmentv1.DepartmentStatus {
	switch strings.ToUpper(status) {
	case string(models.DepartmentStatusActive):
		return departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ACTIVE
	case string(models.DepartmentStatusInactive):
		return departmentv1.DepartmentStatus_DEPARTMENT_STATUS_INACTIVE
	case string(models.DepartmentStatusArchived):
		return departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ARCHIVED
	default:
		return departmentv1.DepartmentStatus_DEPARTMENT_STATUS_UNSPECIFIED
	}
}

func FromProtoDepartmentStatus(status departmentv1.DepartmentStatus) string {
	switch status {
	case departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ACTIVE:
		return string(models.DepartmentStatusActive)
	case departmentv1.DepartmentStatus_DEPARTMENT_STATUS_INACTIVE:
		return string(models.DepartmentStatusInactive)
	case departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ARCHIVED:
		return string(models.DepartmentStatusArchived)
	default:
		return ""
	}
}

func ToProtoDepartmentSortBy(sortBy string) departmentv1.DepartmentSortBy {
	switch strings.ToLower(sortBy) {
	case string(models.DepartmentSortByCreatedAt):
		return departmentv1.DepartmentSortBy_DEPARTMENT_SORT_BY_CREATED_AT
	case string(models.DepartmentSortByUpdatedAt):
		return departmentv1.DepartmentSortBy_DEPARTMENT_SORT_BY_UPDATED_AT
	case string(models.DepartmentSortByName):
		return departmentv1.DepartmentSortBy_DEPARTMENT_SORT_BY_NAME
	case string(models.DepartmentSortByStatus):
		return departmentv1.DepartmentSortBy_DEPARTMENT_SORT_BY_STATUS
	default:
		return departmentv1.DepartmentSortBy_DEPARTMENT_SORT_BY_UNSPECIFIED
	}
}

func ToProtoDepartmentSortOrder(sortOrder string) departmentv1.SortOrder {
	switch strings.ToLower(sortOrder) {
	case string(models.SortOrderAsc):
		return departmentv1.SortOrder_SORT_ORDER_ASC
	case string(models.SortOrderDesc):
		return departmentv1.SortOrder_SORT_ORDER_DESC
	default:
		return departmentv1.SortOrder_SORT_ORDER_UNSPECIFIED
	}
}

func FromProtoDepartment(department *departmentv1.Department) *models.Department {
	if department == nil {
		return nil
	}

	return &models.Department{
		ID:            department.GetId(),
		Name:          department.GetName(),
		Description:   department.GetDescription(),
		Status:        FromProtoDepartmentStatus(department.GetStatus()),
		CreatedAtUnix: timestampUnix(department.GetCreatedAt()),
		UpdatedAtUnix: timestampUnix(department.GetUpdatedAt()),
	}
}
