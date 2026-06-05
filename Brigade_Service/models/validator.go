package models

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	DefaultLimit = int32(20)
	MaxLimit     = int32(100)
)

func (s BrigadeStatus) IsValid() bool {
	switch s {
	case BrigadeStatusActive,
		BrigadeStatusInactive,
		BrigadeStatusAvailable,
		BrigadeStatusBusy,
		BrigadeStatusOnRoute,
		BrigadeStatusOnSite,
		BrigadeStatusOffline,
		BrigadeStatusArchived:
		return true
	default:
		return false
	}
}

func (r BrigadeMemberRole) IsValid() bool {
	switch r {
	case BrigadeMemberRoleLead,
		BrigadeMemberRoleDriver,
		BrigadeMemberRoleTechnician,
		BrigadeMemberRoleTrainee:
		return true
	default:
		return false
	}
}

func (s BrigadeMemberAvailabilityStatus) IsValid() bool {
	switch s {
	case BrigadeMemberAvailabilityAvailable, BrigadeMemberAvailabilityUnavailable:
		return true
	default:
		return false
	}
}

func (a BrigadeMemberHistoryAction) IsValid() bool {
	switch a {
	case BrigadeMemberHistoryActionAdded,
		BrigadeMemberHistoryActionRemoved,
		BrigadeMemberHistoryActionRoleChanged:
		return true
	default:
		return false
	}
}

func (s BrigadeSortBy) IsValid() bool {
	switch s {
	case BrigadeSortByCreatedAt,
		BrigadeSortByUpdatedAt,
		BrigadeSortByName,
		BrigadeSortByStatus:
		return true
	default:
		return false
	}
}

func (s SortOrder) IsValid() bool {
	switch s {
	case SortOrderAsc, SortOrderDesc:
		return true
	default:
		return false
	}
}

func (s OutboxEventStatus) IsValid() bool {
	switch s {
	case OutboxEventStatusPending,
		OutboxEventStatusProcessing,
		OutboxEventStatusSent,
		OutboxEventStatusFailed:
		return true
	default:
		return false
	}
}

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

func validateOptionalUUID(value *uuid.UUID, field string) error {
	if value == nil {
		return nil
	}

	return validateUUID(*value, field)
}

func validateCoordinates(longitude float64, latitude float64) error {
	if longitude < -180 || longitude > 180 {
		return errors.New("longitude must be between -180 and 180")
	}
	if latitude < -90 || latitude > 90 {
		return errors.New("latitude must be between -90 and 90")
	}

	return nil
}

func validateOptionalCoordinates(longitude *float64, latitude *float64) error {
	if longitude == nil && latitude == nil {
		return nil
	}
	if longitude == nil || latitude == nil {
		return errors.New("longitude and latitude must be provided together")
	}

	return validateCoordinates(*longitude, *latitude)
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

func validateRequiredSkillIDs(ids []uuid.UUID) error {
	for i, id := range ids {
		if id == uuid.Nil {
			return fmt.Errorf("required_skill_ids[%d] is required", i)
		}
	}

	return nil
}

func validateTimeRange(from *time.Time, to *time.Time, fromField string, toField string) error {
	if from != nil && to != nil && from.After(*to) {
		return fmt.Errorf("%s must be before %s", fromField, toField)
	}

	return nil
}

func validateScheduleItem(item *BrigadeScheduleItem, index int) error {
	if item == nil {
		return fmt.Errorf("schedule item %d is nil", index)
	}
	if item.DayOfWeek < 1 || item.DayOfWeek > 7 {
		return fmt.Errorf("schedule item %d day_of_week must be between 1 and 7", index)
	}
	if err := validateText(item.StartsAt, fmt.Sprintf("schedule item %d starts_at", index), 16); err != nil {
		return err
	}
	if err := validateText(item.EndsAt, fmt.Sprintf("schedule item %d ends_at", index), 16); err != nil {
		return err
	}
	if item.StartsAt == item.EndsAt {
		return fmt.Errorf("schedule item %d starts_at and ends_at must be different", index)
	}
	if strings.TrimSpace(item.Timezone) != "" {
		if err := validateText(item.Timezone, fmt.Sprintf("schedule item %d timezone", index), 64); err != nil {
			return err
		}
	}

	return validateTimeRange(item.ValidFrom, item.ValidTo, "valid_from", "valid_to")
}

func (in *CreateBrigadeInput) Validate() error {
	if in == nil {
		return errors.New("create brigade input is nil")
	}
	if err := validateUUID(in.DepartmentID, "department_id"); err != nil {
		return err
	}
	if err := validateText(in.Name, "name", 255); err != nil {
		return err
	}
	if strings.TrimSpace(in.Description) != "" {
		if err := validateText(in.Description, "description", 1000); err != nil {
			return err
		}
	}

	return validateOptionalText(in.Specialization, "specialization", 255)
}

func (in *GetBrigadeByIDInput) Validate() error {
	if in == nil {
		return errors.New("get brigade by id input is nil")
	}

	return validateUUID(in.ID, "id")
}

func (in *ListBrigadesInput) Validate() error {
	if in == nil {
		return errors.New("list brigades input is nil")
	}
	if err := validateOptionalUUID(in.DepartmentID, "department_id"); err != nil {
		return err
	}
	if in.Status != nil && !in.Status.IsValid() {
		return ErrInvalidStatus
	}
	if err := validateOptionalText(in.Specialization, "specialization", 255); err != nil {
		return err
	}
	if err := validateTimeRange(in.CreatedFrom, in.CreatedTo, "created_from", "created_to"); err != nil {
		return err
	}
	if in.SortBy == "" {
		in.SortBy = BrigadeSortByCreatedAt
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

func (in *UpdateBrigadeInput) Validate() error {
	if in == nil {
		return errors.New("update brigade input is nil")
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
	if err := validateOptionalText(in.Specialization, "specialization", 255); err != nil {
		return err
	}
	if in.Name == nil && in.Description == nil && in.Specialization == nil {
		return errors.New("at least one field must be provided for update")
	}

	return nil
}

func (in *DeactivateBrigadeInput) Validate() error {
	if in == nil {
		return errors.New("deactivate brigade input is nil")
	}

	return validateUUID(in.ID, "id")
}

func (in *ArchiveBrigadeInput) Validate() error {
	if in == nil {
		return errors.New("archive brigade input is nil")
	}

	return validateUUID(in.ID, "id")
}

func (in *SetBrigadeStatusInput) Validate() error {
	if in == nil {
		return errors.New("set brigade status input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}
	if !in.Status.IsValid() {
		return ErrInvalidStatus
	}

	return nil
}

func (in *GetBrigadeStatusHistoryInput) Validate() error {
	if in == nil {
		return errors.New("get brigade status history input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}

	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)
	return nil
}

func (in *AddBrigadeMemberInput) Validate() error {
	if in == nil {
		return errors.New("add brigade member input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}
	if err := validateUUID(in.UserID, "user_id"); err != nil {
		return err
	}
	if err := validateOptionalUUID(in.ProfileID, "profile_id"); err != nil {
		return err
	}
	if !in.Role.IsValid() {
		return ErrInvalidRole
	}

	return nil
}

func (in *RemoveBrigadeMemberInput) Validate() error {
	if in == nil {
		return errors.New("remove brigade member input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}

	return validateUUID(in.MemberID, "member_id")
}

func (in *ChangeBrigadeMemberRoleInput) Validate() error {
	if in == nil {
		return errors.New("change brigade member role input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}
	if err := validateUUID(in.MemberID, "member_id"); err != nil {
		return err
	}
	if !in.Role.IsValid() {
		return ErrInvalidRole
	}

	return nil
}

func (in *SetBrigadeMemberAvailabilityInput) Validate() error {
	if in == nil {
		return errors.New("set brigade member availability input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}
	if err := validateUUID(in.MemberID, "member_id"); err != nil {
		return err
	}
	if !in.Status.IsValid() {
		return ErrInvalidAvailability
	}

	return nil
}

func (in *ListBrigadeMembersInput) Validate() error {
	if in == nil {
		return errors.New("list brigade members input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}
	if in.Role != nil && !in.Role.IsValid() {
		return ErrInvalidRole
	}
	if in.AvailabilityStatus != nil && !in.AvailabilityStatus.IsValid() {
		return ErrInvalidAvailability
	}

	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)
	return nil
}

func (in *GetBrigadeMemberHistoryInput) Validate() error {
	if in == nil {
		return errors.New("get brigade member history input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}
	if err := validateOptionalUUID(in.MemberID, "member_id"); err != nil {
		return err
	}

	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)
	return nil
}

func (in *GetBrigadeMemberStatusHistoryInput) Validate() error {
	if in == nil {
		return errors.New("get brigade member status history input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}
	if err := validateOptionalUUID(in.MemberID, "member_id"); err != nil {
		return err
	}

	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)
	return nil
}

func (in *GetBrigadeByUserIDInput) Validate() error {
	if in == nil {
		return errors.New("get brigade by user id input is nil")
	}

	return validateUUID(in.UserID, "user_id")
}

func (in *CreateSkillInput) Validate() error {
	if in == nil {
		return errors.New("create skill input is nil")
	}
	if err := validateText(in.Code, "code", 100); err != nil {
		return err
	}
	if err := validateText(in.Name, "name", 255); err != nil {
		return err
	}
	if strings.TrimSpace(in.Description) != "" {
		return validateText(in.Description, "description", 1000)
	}

	return nil
}

func (in *UpdateSkillInput) Validate() error {
	if in == nil {
		return errors.New("update skill input is nil")
	}
	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}
	if err := validateOptionalText(in.Code, "code", 100); err != nil {
		return err
	}
	if err := validateOptionalText(in.Name, "name", 255); err != nil {
		return err
	}
	if err := validateOptionalText(in.Description, "description", 1000); err != nil {
		return err
	}
	if in.Code == nil && in.Name == nil && in.Description == nil && in.Active == nil {
		return errors.New("at least one field must be provided for update")
	}

	return nil
}

func (in *DeactivateSkillInput) Validate() error {
	if in == nil {
		return errors.New("deactivate skill input is nil")
	}

	return validateUUID(in.ID, "id")
}

func (in *ListSkillsInput) Validate() error {
	if in == nil {
		return errors.New("list skills input is nil")
	}
	if err := validateOptionalText(in.Query, "query", 255); err != nil {
		return err
	}

	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)
	return nil
}

func (in *AddBrigadeSkillInput) Validate() error {
	if in == nil {
		return errors.New("add brigade skill input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}

	return validateUUID(in.SkillID, "skill_id")
}

func (in *RemoveBrigadeSkillInput) Validate() error {
	if in == nil {
		return errors.New("remove brigade skill input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}

	return validateUUID(in.SkillID, "skill_id")
}

func (in *ListBrigadeSkillsInput) Validate() error {
	if in == nil {
		return errors.New("list brigade skills input is nil")
	}

	return validateUUID(in.BrigadeID, "brigade_id")
}

func (in *SetBrigadeScheduleInput) Validate() error {
	if in == nil {
		return errors.New("set brigade schedule input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}
	if len(in.Items) == 0 {
		return errors.New("schedule items are required")
	}
	for i, item := range in.Items {
		if err := validateScheduleItem(item, i); err != nil {
			return err
		}
	}

	return nil
}

func (in *ListBrigadeScheduleInput) Validate() error {
	if in == nil {
		return errors.New("list brigade schedule input is nil")
	}

	return validateUUID(in.BrigadeID, "brigade_id")
}

func (in *CreateBrigadeZoneInput) Validate() error {
	if in == nil {
		return errors.New("create brigade zone input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}
	if err := validateUUID(in.DepartmentID, "department_id"); err != nil {
		return err
	}
	if err := validateText(in.Name, "name", 255); err != nil {
		return err
	}
	if err := validateText(in.GeoJSON, "geo_json", 1_000_000); err != nil {
		return ErrInvalidGeometry
	}

	return nil
}

func (in *UpdateBrigadeZoneInput) Validate() error {
	if in == nil {
		return errors.New("update brigade zone input is nil")
	}
	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}
	if err := validateOptionalText(in.Name, "name", 255); err != nil {
		return err
	}
	if in.GeoJSON != nil {
		if err := validateText(*in.GeoJSON, "geo_json", 1_000_000); err != nil {
			return ErrInvalidGeometry
		}
	}
	if in.Name == nil && in.GeoJSON == nil && in.Priority == nil && in.Active == nil {
		return errors.New("at least one field must be provided for update")
	}

	return nil
}

func (in *DeleteBrigadeZoneInput) Validate() error {
	if in == nil {
		return errors.New("delete brigade zone input is nil")
	}

	return validateUUID(in.ID, "id")
}

func (in *ListBrigadeZonesInput) Validate() error {
	if in == nil {
		return errors.New("list brigade zones input is nil")
	}

	return validateUUID(in.BrigadeID, "brigade_id")
}

func (in *CheckBrigadeCoversPointInput) Validate() error {
	if in == nil {
		return errors.New("check brigade covers point input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}

	return validateCoordinates(in.Longitude, in.Latitude)
}

func (in *FindBrigadesByPointInput) Validate() error {
	if in == nil {
		return errors.New("find brigades by point input is nil")
	}
	if err := validateUUID(in.DepartmentID, "department_id"); err != nil {
		return err
	}
	if err := validateCoordinates(in.Longitude, in.Latitude); err != nil {
		return err
	}
	if err := validateRequiredSkillIDs(in.RequiredSkillIDs); err != nil {
		return err
	}

	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)
	return nil
}

func (in *GetAvailableBrigadesInput) Validate() error {
	if in == nil {
		return errors.New("get available brigades input is nil")
	}
	if err := validateUUID(in.DepartmentID, "department_id"); err != nil {
		return err
	}
	if err := validateOptionalCoordinates(in.Longitude, in.Latitude); err != nil {
		return err
	}
	if err := validateRequiredSkillIDs(in.RequiredSkillIDs); err != nil {
		return err
	}

	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)
	return nil
}

func (in *CheckBrigadeCanHandleTicketInput) Validate() error {
	if in == nil {
		return errors.New("check brigade can handle ticket input is nil")
	}
	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}
	if err := validateUUID(in.DepartmentID, "department_id"); err != nil {
		return err
	}
	if err := validateCoordinates(in.Longitude, in.Latitude); err != nil {
		return err
	}

	return validateRequiredSkillIDs(in.RequiredSkillIDs)
}
