package models

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	DefaultLimit = int32(20)
	MaxLimit     = int32(100)
)

var phonePattern = regexp.MustCompile(`^\+[0-9]{8,15}$`)

func (m PreferredContactMethod) IsValid() bool {
	switch m {
	case PreferredContactMethodEmail, PreferredContactMethodPhone, PreferredContactMethodPush:
		return true
	default:
		return false
	}
}

func (s WorkProfileStatus) IsValid() bool {
	switch s {
	case WorkProfileStatusActive,
		WorkProfileStatusInactive,
		WorkProfileStatusOnShift,
		WorkProfileStatusOffShift,
		WorkProfileStatusSuspended:
		return true
	default:
		return false
	}
}

func (s UserProfileSortBy) IsValid() bool {
	switch s {
	case UserProfileSortByCreatedAt, UserProfileSortByUpdatedAt, UserProfileSortByFullName:
		return true
	default:
		return false
	}
}

func (s WorkProfileSortBy) IsValid() bool {
	switch s {
	case WorkProfileSortByCreatedAt,
		WorkProfileSortByUpdatedAt,
		WorkProfileSortByFullName,
		WorkProfileSortByPosition,
		WorkProfileSortByStatus,
		WorkProfileSortByEmployeeNumber:
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

func (r CanJoinBrigadeReason) IsValid() bool {
	switch r {
	case CanJoinBrigadeReasonAllowed,
		CanJoinBrigadeReasonNoWorkProfile,
		CanJoinBrigadeReasonProfileInactive,
		CanJoinBrigadeReasonProfileSuspended,
		CanJoinBrigadeReasonProfileOffShift,
		CanJoinBrigadeReasonDepartmentMismatch:
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

func (s CertificationStatus) IsValid() bool {
	switch s {
	case CertificationStatusPending,
		CertificationStatusVerified,
		CertificationStatusRejected,
		CertificationStatusExpired,
		CertificationStatusRevoked:
		return true
	default:
		return false
	}
}

func (s SkillGrantSourceType) IsValid() bool {
	switch s {
	case SkillGrantSourceTypeManual, SkillGrantSourceTypeCertification:
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

func validateOptionalUUID(value *uuid.UUID, field string) error {
	if value == nil {
		return nil
	}
	return validateUUID(*value, field)
}

func validateText(value string, field string, minLen int, maxLen int) error {
	value = strings.TrimSpace(value)
	length := utf8.RuneCountInString(value)
	if length < minLen {
		if minLen == 1 {
			return fmt.Errorf("%s is required", field)
		}
		return fmt.Errorf("%s must contain at least %d characters", field, minLen)
	}
	if length > maxLen {
		return fmt.Errorf("%s must contain at most %d characters", field, maxLen)
	}
	return nil
}

func validateOptionalText(value *string, field string, minLen int, maxLen int) error {
	if value == nil {
		return nil
	}
	return validateText(*value, field, minLen, maxLen)
}

func validatePhone(value *string, field string) error {
	if value == nil {
		return nil
	}
	phone := strings.TrimSpace(*value)
	if !phonePattern.MatchString(phone) {
		return fmt.Errorf("%s must be in E.164 format", field)
	}
	return nil
}

func validateOptionalPositiveInt32(value *int32, field string) error {
	if value == nil {
		return nil
	}
	if *value <= 0 {
		return fmt.Errorf("%s must be greater than zero", field)
	}
	return nil
}

func validateDateRange(from *time.Time, to *time.Time, fromField string, toField string) error {
	if from != nil && to != nil && to.Before(*from) {
		return fmt.Errorf("%s cannot be earlier than %s", toField, fromField)
	}
	return nil
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

func (in *CreateUserProfileInput) Validate() error {
	if in == nil {
		return errors.New("create user profile input is nil")
	}
	if err := validateUUID(in.UserID, "user_id"); err != nil {
		return err
	}
	if err := validateText(in.FullName, "full_name", 2, 255); err != nil {
		return err
	}
	if err := validatePhone(in.Phone, "phone"); err != nil {
		return err
	}
	if err := validateOptionalUUID(in.AvatarFileID, "avatar_file_id"); err != nil {
		return err
	}
	if in.PreferredContactMethod == "" {
		in.PreferredContactMethod = PreferredContactMethodEmail
	}
	if !in.PreferredContactMethod.IsValid() {
		return ErrInvalidContactMethod
	}
	if in.PreferredContactMethod == PreferredContactMethodPhone && in.Phone == nil {
		return errors.New("phone is required when preferred_contact_method is PHONE")
	}
	return nil
}

func (in *GetUserProfileByIDInput) Validate() error {
	if in == nil {
		return errors.New("get user profile by id input is nil")
	}
	return validateUUID(in.ID, "id")
}

func (in *GetUserProfileByUserIDInput) Validate() error {
	if in == nil {
		return errors.New("get user profile by user id input is nil")
	}
	return validateUUID(in.UserID, "user_id")
}

func (in *GetMyUserProfileInput) Validate() error {
	if in == nil {
		return errors.New("get my user profile input is nil")
	}
	if in.ActorUserID == nil {
		return errors.New("actor_user_id is required")
	}
	return validateUUID(*in.ActorUserID, "actor_user_id")
}

func (in *ListUserProfilesInput) Validate() error {
	if in == nil {
		return errors.New("list user profiles input is nil")
	}
	if err := validateOptionalText(in.Query, "query", 1, 255); err != nil {
		return err
	}
	if in.SortBy == "" {
		in.SortBy = UserProfileSortByCreatedAt
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

func (in *UpdateUserProfileInput) Validate() error {
	if in == nil {
		return errors.New("update user profile input is nil")
	}
	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}
	if err := validateOptionalText(in.FullName, "full_name", 2, 255); err != nil {
		return err
	}
	if err := validatePhone(in.Phone, "phone"); err != nil {
		return err
	}
	if err := validateOptionalUUID(in.AvatarFileID, "avatar_file_id"); err != nil {
		return err
	}
	if in.PreferredContactMethod != nil && !in.PreferredContactMethod.IsValid() {
		return ErrInvalidContactMethod
	}
	if in.Phone != nil && in.ClearPhone {
		return errors.New("phone and clear_phone cannot be provided together")
	}
	if in.AvatarFileID != nil && in.ClearAvatarFileID {
		return errors.New("avatar_file_id and clear_avatar_file_id cannot be provided together")
	}
	if in.ClearPhone && in.PreferredContactMethod != nil && *in.PreferredContactMethod == PreferredContactMethodPhone {
		return errors.New("phone cannot be cleared when preferred_contact_method is PHONE")
	}
	if in.FullName == nil && in.Phone == nil && !in.ClearPhone && in.AvatarFileID == nil && !in.ClearAvatarFileID && in.PreferredContactMethod == nil {
		return errors.New("at least one field must be provided for update")
	}
	return nil
}

func (in *CreateWorkProfileInput) Validate() error {
	if in == nil {
		return errors.New("create work profile input is nil")
	}
	if err := validateUUID(in.UserProfileID, "user_profile_id"); err != nil {
		return err
	}
	if err := validateUUID(in.DepartmentID, "department_id"); err != nil {
		return err
	}
	if err := validateOptionalText(in.EmployeeNumber, "employee_number", 1, 64); err != nil {
		return err
	}
	return validateText(in.Position, "position", 2, 128)
}

func (in *GetWorkProfileByIDInput) Validate() error {
	if in == nil {
		return errors.New("get work profile by id input is nil")
	}
	return validateUUID(in.ID, "id")
}

func (in *GetWorkProfileByUserIDInput) Validate() error {
	if in == nil {
		return errors.New("get work profile by user id input is nil")
	}
	return validateUUID(in.UserID, "user_id")
}

func (in *ListWorkProfilesInput) Validate() error {
	if in == nil {
		return errors.New("list work profiles input is nil")
	}
	if err := validateOptionalUUID(in.DepartmentID, "department_id"); err != nil {
		return err
	}
	if in.Status != nil && !in.Status.IsValid() {
		return ErrInvalidStatus
	}
	if err := validateOptionalText(in.Query, "query", 1, 255); err != nil {
		return err
	}
	if in.SortBy == "" {
		in.SortBy = WorkProfileSortByCreatedAt
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

func (in *UpdateWorkProfileInput) Validate() error {
	if in == nil {
		return errors.New("update work profile input is nil")
	}
	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}
	if err := validateOptionalText(in.EmployeeNumber, "employee_number", 1, 64); err != nil {
		return err
	}
	if err := validateOptionalText(in.Position, "position", 2, 128); err != nil {
		return err
	}
	if in.EmployeeNumber != nil && in.ClearEmployeeNumber {
		return errors.New("employee_number and clear_employee_number cannot be provided together")
	}
	if in.EmployeeNumber == nil && !in.ClearEmployeeNumber && in.Position == nil {
		return errors.New("at least one field must be provided for update")
	}
	return nil
}

func (in *DeactivateWorkProfileInput) Validate() error {
	if in == nil {
		return errors.New("deactivate work profile input is nil")
	}
	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}
	return validateText(in.Reason, "reason", 1, 1000)
}

func (in *ChangeWorkProfileDepartmentInput) Validate() error {
	if in == nil {
		return errors.New("change work profile department input is nil")
	}
	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}
	if err := validateUUID(in.DepartmentID, "department_id"); err != nil {
		return err
	}
	return validateText(in.Reason, "reason", 1, 1000)
}

func (in *SetWorkProfileStatusInput) Validate() error {
	if in == nil {
		return errors.New("set work profile status input is nil")
	}
	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}
	if !in.Status.IsValid() {
		return ErrInvalidStatus
	}
	return validateText(in.Reason, "reason", 1, 1000)
}

func (in *GetWorkProfileStatusHistoryInput) Validate() error {
	if in == nil {
		return errors.New("get work profile status history input is nil")
	}
	if err := validateUUID(in.WorkProfileID, "work_profile_id"); err != nil {
		return err
	}
	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)
	return nil
}

func (in *ResolveWorkingDepartmentInput) Validate() error {
	if in == nil {
		return errors.New("resolve working department input is nil")
	}
	return validateUUID(in.UserID, "user_id")
}

func (in *CheckProfileCanJoinBrigadeInput) Validate() error {
	if in == nil {
		return errors.New("check profile can join brigade input is nil")
	}
	if (in.UserID == nil) == (in.WorkProfileID == nil) {
		return errors.New("exactly one of user_id or work_profile_id must be provided")
	}
	if err := validateOptionalUUID(in.UserID, "user_id"); err != nil {
		return err
	}
	if err := validateOptionalUUID(in.WorkProfileID, "work_profile_id"); err != nil {
		return err
	}
	return validateUUID(in.BrigadeDepartmentID, "brigade_department_id")
}

func (in *CreateCertificationTypeInput) Validate() error {
	if in == nil {
		return errors.New("create certification type input is nil")
	}
	if err := validateText(in.Code, "code", 2, 64); err != nil {
		return err
	}
	if err := validateText(in.Name, "name", 2, 255); err != nil {
		return err
	}
	if err := validateOptionalText(in.Description, "description", 1, 2000); err != nil {
		return err
	}
	return validateOptionalPositiveInt32(in.DefaultValidityDays, "default_validity_days")
}

func (in *UpdateCertificationTypeInput) Validate() error {
	if in == nil {
		return errors.New("update certification type input is nil")
	}
	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}
	if err := validateOptionalText(in.Code, "code", 2, 64); err != nil {
		return err
	}
	if err := validateOptionalText(in.Name, "name", 2, 255); err != nil {
		return err
	}
	if err := validateOptionalText(in.Description, "description", 1, 2000); err != nil {
		return err
	}
	if err := validateOptionalPositiveInt32(in.DefaultValidityDays, "default_validity_days"); err != nil {
		return err
	}
	if in.Description != nil && in.ClearDescription {
		return errors.New("description and clear_description cannot be provided together")
	}
	if in.DefaultValidityDays != nil && in.ClearValidityDays {
		return errors.New("default_validity_days and clear_validity_days cannot be provided together")
	}
	if in.Code == nil && in.Name == nil && in.Description == nil && !in.ClearDescription &&
		in.DefaultValidityDays == nil && !in.ClearValidityDays && in.RequiresFile == nil && in.Active == nil {
		return errors.New("at least one field must be provided for update")
	}
	return nil
}

func (in *ListCertificationTypesInput) Validate() error {
	if in == nil {
		return errors.New("list certification types input is nil")
	}
	if err := validateOptionalText(in.Query, "query", 1, 255); err != nil {
		return err
	}
	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)
	return nil
}

func (in *AddCertificationTypeSkillInput) Validate() error {
	if in == nil {
		return errors.New("add certification type skill input is nil")
	}
	if err := validateUUID(in.CertificationTypeID, "certification_type_id"); err != nil {
		return err
	}
	if err := validateUUID(in.SkillID, "skill_id"); err != nil {
		return err
	}
	return validateOptionalText(in.ProficiencyLevel, "proficiency_level", 1, 64)
}

func (in *RemoveCertificationTypeSkillInput) Validate() error {
	if in == nil {
		return errors.New("remove certification type skill input is nil")
	}
	if err := validateUUID(in.CertificationTypeID, "certification_type_id"); err != nil {
		return err
	}
	return validateUUID(in.SkillID, "skill_id")
}

func (in *ListCertificationTypeSkillsInput) Validate() error {
	if in == nil {
		return errors.New("list certification type skills input is nil")
	}
	return validateUUID(in.CertificationTypeID, "certification_type_id")
}

func (in *UploadWorkProfileCertificationInput) Validate() error {
	if in == nil {
		return errors.New("upload work profile certification input is nil")
	}
	if err := validateUUID(in.WorkProfileID, "work_profile_id"); err != nil {
		return err
	}
	if err := validateUUID(in.CertificationTypeID, "certification_type_id"); err != nil {
		return err
	}
	if err := validateOptionalText(in.CertificateNumber, "certificate_number", 1, 128); err != nil {
		return err
	}
	if err := validateOptionalText(in.Issuer, "issuer", 1, 255); err != nil {
		return err
	}
	if err := validateOptionalUUID(in.CertificateFileID, "certificate_file_id"); err != nil {
		return err
	}
	return validateDateRange(in.IssuedAt, in.ExpiresAt, "issued_at", "expires_at")
}

func (in *VerifyWorkProfileCertificationInput) Validate() error {
	if in == nil {
		return errors.New("verify work profile certification input is nil")
	}
	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}
	if in.ActorUserID == nil {
		return errors.New("actor_user_id is required")
	}
	return validateUUID(*in.ActorUserID, "actor_user_id")
}

func (in *RejectWorkProfileCertificationInput) Validate() error {
	if in == nil {
		return errors.New("reject work profile certification input is nil")
	}
	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}
	return validateText(in.RejectionReason, "rejection_reason", 1, 1000)
}

func (in *RevokeWorkProfileCertificationInput) Validate() error {
	if in == nil {
		return errors.New("revoke work profile certification input is nil")
	}
	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}
	return validateText(in.Reason, "reason", 1, 1000)
}

func (in *ExpireWorkProfileCertificationsInput) Validate() error {
	if in == nil {
		return errors.New("expire work profile certifications input is nil")
	}
	in.Limit, _ = normalizeLimitOffset(in.Limit, 0)
	return nil
}

func (in *ListWorkProfileCertificationsInput) Validate() error {
	if in == nil {
		return errors.New("list work profile certifications input is nil")
	}
	if err := validateUUID(in.WorkProfileID, "work_profile_id"); err != nil {
		return err
	}
	if err := validateOptionalUUID(in.CertificationTypeID, "certification_type_id"); err != nil {
		return err
	}
	if in.Status != nil && !in.Status.IsValid() {
		return ErrInvalidCertificationStatus
	}
	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)
	return nil
}

func (in *GrantManualWorkProfileSkillInput) Validate() error {
	if in == nil {
		return errors.New("grant manual work profile skill input is nil")
	}
	if err := validateUUID(in.WorkProfileID, "work_profile_id"); err != nil {
		return err
	}
	if err := validateUUID(in.SkillID, "skill_id"); err != nil {
		return err
	}
	if err := validateOptionalText(in.ProficiencyLevel, "proficiency_level", 1, 64); err != nil {
		return err
	}
	if in.ValidUntil != nil && !in.ValidUntil.After(time.Now()) {
		return errors.New("valid_until must be in the future")
	}
	return validateText(in.Reason, "reason", 1, 1000)
}

func (in *RevokeWorkProfileSkillGrantInput) Validate() error {
	if in == nil {
		return errors.New("revoke work profile skill grant input is nil")
	}
	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}
	return validateText(in.Reason, "reason", 1, 1000)
}

func (in *ListEffectiveWorkProfileSkillsInput) Validate() error {
	if in == nil {
		return errors.New("list effective work profile skills input is nil")
	}
	return validateUUID(in.WorkProfileID, "work_profile_id")
}

func (in *BatchListEffectiveWorkProfileSkillsInput) Validate() error {
	if in == nil {
		return errors.New("batch list effective work profile skills input is nil")
	}
	if len(in.WorkProfileIDs) == 0 {
		return errors.New("work_profile_ids is required")
	}
	if len(in.WorkProfileIDs) > int(MaxLimit) {
		return fmt.Errorf("work_profile_ids must contain at most %d items", MaxLimit)
	}
	seen := make(map[uuid.UUID]struct{}, len(in.WorkProfileIDs))
	for _, id := range in.WorkProfileIDs {
		if err := validateUUID(id, "work_profile_ids"); err != nil {
			return err
		}
		if _, ok := seen[id]; ok {
			return errors.New("work_profile_ids contains duplicates")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func (in *CheckWorkProfileHasSkillsInput) Validate() error {
	if in == nil {
		return errors.New("check work profile has skills input is nil")
	}
	if err := validateUUID(in.WorkProfileID, "work_profile_id"); err != nil {
		return err
	}
	if len(in.RequiredSkillIDs) == 0 {
		return errors.New("required_skill_ids is required")
	}
	seen := make(map[uuid.UUID]struct{}, len(in.RequiredSkillIDs))
	for _, id := range in.RequiredSkillIDs {
		if err := validateUUID(id, "required_skill_ids"); err != nil {
			return err
		}
		if _, ok := seen[id]; ok {
			return errors.New("required_skill_ids contains duplicates")
		}
		seen[id] = struct{}{}
	}
	return nil
}
