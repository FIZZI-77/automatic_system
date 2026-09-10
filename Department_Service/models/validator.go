package models

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

const (
	DefaultLimit = int32(20)
	MaxLimit     = int32(100)
)

func validateUUID(value uuid.UUID, field string) error {
	if value == uuid.Nil {
		return fmt.Errorf("%s is required", field)
	}

	return nil
}

func validateText(value string, field string, maxLen int) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}

	if len(value) > maxLen {
		return fmt.Errorf("%s must be less than %d characters", field, maxLen)
	}

	return nil
}

func validateOptionalText(value *string, field string, maxLen int) error {
	if value == nil {
		return nil
	}

	return validateText(*value, field, maxLen)
}

func normalizeLimitOffset(limit int32, offset int32) (int32, int32) {
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	if offset < 0 {
		offset = 0
	}

	return limit, offset
}

func (in *CreateDepartmentInput) Validate() error {
	if in == nil {
		return errors.New("create department input is nil")
	}

	if err := validateText(in.Name, "name", 255); err != nil {
		return err
	}

	if strings.TrimSpace(in.Description) != "" {
		if err := validateText(in.Description, "description", 1000); err != nil {
			return err
		}
	}

	return nil
}

func (in *GetDepartmentByIDInput) Validate() error {
	if in == nil {
		return errors.New("get department input is nil")
	}

	return validateUUID(in.ID, "id")
}

func (in *ListDepartmentsInput) Validate() error {
	if in == nil {
		return errors.New("list departments input is nil")
	}

	if in.Status != nil && !in.Status.IsValid() {
		return errors.New("status is invalid")
	}

	if in.CreatedFrom != nil && in.CreatedTo != nil && in.CreatedFrom.After(*in.CreatedTo) {
		return errors.New("created_from must be before created_to")
	}

	if in.SortBy == "" {
		in.SortBy = DepartmentSortByCreatedAt
	}
	if !in.SortBy.IsValid() {
		return errors.New("sort_by is invalid")
	}

	if in.SortOrder == "" {
		in.SortOrder = SortOrderDesc
	}
	if !in.SortOrder.IsValid() {
		return errors.New("sort_order is invalid")
	}

	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)
	return nil
}

func (in *UpdateDepartmentInput) Validate() error {
	if in == nil {
		return errors.New("update department input is nil")
	}

	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}

	if err := validateOptionalText(in.Name, "name", 255); err != nil {
		return err
	}

	if err := validateOptionalText(in.Description, "description", 1000); err != nil {
		return err
	}

	if in.Status != nil && !in.Status.IsValid() {
		return errors.New("status is invalid")
	}

	if in.Name == nil && in.Description == nil && in.Status == nil {
		return errors.New("at least one field must be provided for update")
	}

	return nil
}

func (in *DeleteDepartmentInput) Validate() error {
	if in == nil {
		return errors.New("delete department input is nil")
	}

	return validateUUID(in.ID, "id")
}
