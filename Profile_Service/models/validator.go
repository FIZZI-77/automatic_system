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

// IsValid проверяет способ связи: EMAIL, PHONE или PUSH.
func (m PreferredContactMethod) IsValid() bool {
	switch m {
	case PreferredContactMethodEmail, PreferredContactMethodPhone, PreferredContactMethodPush:
		return true
	default:
		return false
	}
}

// IsValid проверяет статус рабочего профиля: ACTIVE, INACTIVE, ON_SHIFT, OFF_SHIFT или SUSPENDED.
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

// IsValid проверяет поле сортировки пользовательских профилей: время создания, обновления или полное имя.
func (s UserProfileSortBy) IsValid() bool {
	switch s {
	case UserProfileSortByCreatedAt, UserProfileSortByUpdatedAt, UserProfileSortByFullName:
		return true
	default:
		return false
	}
}

// IsValid проверяет поле сортировки рабочих профилей: время создания, обновления,
// полное имя, должность, статус или табельный номер.
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

// IsValid проверяет направление asc или desc с учётом регистра.
func (s SortOrder) IsValid() bool {
	switch s {
	case SortOrderAsc, SortOrderDesc:
		return true
	default:
		return false
	}
}

// IsValid проверяет известную причину разрешения или отказа во включении в бригаду:
// допуск, отсутствие профиля, неактивность, приостановка, отсутствие смены или другое ведомство.
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

// IsValid проверяет статус outbox: PENDING, PROCESSING, SENT или FAILED.
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

// IsValid проверяет статус сертификата: PENDING, VERIFIED, REJECTED, EXPIRED или REVOKED.
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

// IsValid проверяет источник навыка: MANUAL или CERTIFICATION.
func (s SkillGrantSourceType) IsValid() bool {
	switch s {
	case SkillGrantSourceTypeManual, SkillGrantSourceTypeCertification:
		return true
	default:
		return false
	}
}

// validateUUID отклоняет нулевой UUID, указывая обязательное поле field в ошибке.
func validateUUID(value uuid.UUID, field string) error {

	if value == uuid.Nil {
		return fmt.Errorf("%s is required", field)
	}

	return nil
}

// validateOptionalUUID допускает nil, а заданный UUID требует ненулевым.
func validateOptionalUUID(value *uuid.UUID, field string) error {

	if value == nil {
		return nil
	}

	return validateUUID(*value, field)
}

// validateText проверяет число Unicode-символов после удаления крайних пробелов
// в пределах [minLen, maxLen]. Исходную строку не изменяет.
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

// validateOptionalText допускает nil, а заданную строку проверяет через validateText.
func validateOptionalText(value *string, field string, minLen int, maxLen int) error {

	if value == nil {
		return nil
	}

	return validateText(*value, field, minLen, maxLen)
}

// validatePhone допускает nil, иначе требует плюс и 8–15 цифр после удаления
// крайних пробелов. Исходную строку телефона не изменяет.
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

// validateOptionalPositiveInt32 допускает nil, а заданное значение требует больше нуля.
func validateOptionalPositiveInt32(value *int32, field string) error {

	if value == nil {
		return nil
	}

	if *value <= 0 {
		return fmt.Errorf("%s must be greater than zero", field)
	}

	return nil
}

// validateDateRange отклоняет конец раньше начала, если обе даты заданы.
// Равные даты и отсутствие одной из границ допустимы.
func validateDateRange(from *time.Time, to *time.Time, fromField string, toField string) error {

	if from != nil && to != nil && to.Before(*from) {
		return fmt.Errorf("%s cannot be earlier than %s", toField, fromField)
	}

	return nil
}

// normalizeLimitOffset задаёт DefaultLimit для неположительного лимита,
// ограничивает его MaxLimit и заменяет отрицательное смещение нулём.
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

// Validate проверяет пользователя, имя 2–255 символов, телефон и аватар.
// Пустой способ связи в in заменяет на EMAIL; PHONE требует заданный телефон.
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

// Validate требует ненулевой запрос и ID пользовательского профиля.
func (in *GetUserProfileByIDInput) Validate() error {

	if in == nil {
		return errors.New("get user profile by id input is nil")
	}

	return validateUUID(in.ID, "id")
}

// Validate требует ненулевой запрос и ID пользователя.
func (in *GetUserProfileByUserIDInput) Validate() error {

	if in == nil {
		return errors.New("get user profile by user id input is nil")
	}

	return validateUUID(in.UserID, "user_id")
}

// Validate требует ненулевой запрос и заданный ненулевой ActorUserID.
func (in *GetMyUserProfileInput) Validate() error {

	if in == nil {
		return errors.New("get my user profile input is nil")
	}

	if in.ActorUserID == nil {
		return errors.New("actor_user_id is required")
	}

	return validateUUID(*in.ActorUserID, "actor_user_id")
}

// Validate проверяет поисковую строку 1–255 символов и сортировку.
// Задаёт в in пустую сортировку по времени создания DESC и нормализует пагинацию;
// при поздней ошибке ранее внесённые значения сохраняются.
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

// Validate проверяет ID и заданные поля профиля, требует хотя бы одно изменение.
// Запрещает одновременно задавать и очищать телефон или аватар, а также очищать
// телефон при явно выбранном способе PHONE. in не изменяет.
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

// Validate требует ID пользовательского профиля и ведомства, должность 2–128 символов
// и, если задан, табельный номер 1–64 символа. in не изменяет.
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

// Validate требует ненулевой запрос и ID рабочего профиля.
func (in *GetWorkProfileByIDInput) Validate() error {

	if in == nil {
		return errors.New("get work profile by id input is nil")
	}

	return validateUUID(in.ID, "id")
}

// Validate требует ненулевой запрос и ID пользователя рабочего профиля.
func (in *GetWorkProfileByUserIDInput) Validate() error {

	if in == nil {
		return errors.New("get work profile by user id input is nil")
	}

	return validateUUID(in.UserID, "user_id")
}

// Validate проверяет ведомство, статус, поисковую строку и сортировку.
// Задаёт в in пустую сортировку по времени создания DESC и нормализует пагинацию;
// при поздней ошибке ранее внесённые значения сохраняются.
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

// Validate требует ID и изменение должности либо табельного номера, проверяя длины.
// Одновременные EmployeeNumber и ClearEmployeeNumber отклоняет; in не изменяет.
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

// Validate требует ID рабочего профиля и причину деактивации длиной 1–1000 символов.
func (in *DeactivateWorkProfileInput) Validate() error {

	if in == nil {
		return errors.New("deactivate work profile input is nil")
	}

	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}

	return validateText(in.Reason, "reason", 1, 1000)
}

// Validate требует ID профиля, нового ведомства и причину длиной 1–1000 символов.
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

// Validate требует ID профиля, известный статус и причину длиной 1–1000 символов.
// Допустимость перехода между статусами не проверяет.
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

// Validate требует ID рабочего профиля и нормализует Limit и Offset непосредственно в in.
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

// Validate требует ненулевой запрос и ID пользователя для определения рабочего ведомства.
func (in *ResolveWorkingDepartmentInput) Validate() error {

	if in == nil {
		return errors.New("resolve working department input is nil")
	}

	return validateUUID(in.UserID, "user_id")
}

// Validate требует ровно один ненулевой идентификатор пользователя или рабочего
// профиля и ненулевой ID ведомства бригады. Возможность вступления не проверяет.
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

// Validate проверяет код 2–64, имя 2–255 и необязательное описание 1–2000 символов,
// а также положительный заданный срок действия в днях. in не изменяет.
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

// Validate требует ID типа сертификата и хотя бы одно изменение, проверяет длины
// текста и положительный заданный срок действия. Запрещает одновременно задавать
// и очищать описание или срок; in не изменяет.
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

// Validate проверяет необязательную поисковую строку 1–255 символов
// и нормализует Limit и Offset в in.
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

// Validate требует ID типа сертификата и навыка и проверяет необязательный
// уровень владения длиной 1–64 символа.
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

// Validate требует ненулевые ID типа сертификата и удаляемой связи с навыком.
func (in *RemoveCertificationTypeSkillInput) Validate() error {

	if in == nil {
		return errors.New("remove certification type skill input is nil")
	}

	if err := validateUUID(in.CertificationTypeID, "certification_type_id"); err != nil {
		return err
	}

	return validateUUID(in.SkillID, "skill_id")
}

// Validate требует ненулевой запрос и ID типа сертификата для списка навыков.
func (in *ListCertificationTypeSkillsInput) Validate() error {

	if in == nil {
		return errors.New("list certification type skills input is nil")
	}

	return validateUUID(in.CertificationTypeID, "certification_type_id")
}

// Validate требует ID рабочего профиля и типа сертификата, проверяет номер,
// издателя, заданный ID файла и порядок дат выдачи и окончания. in не изменяет.
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

// Validate требует ID сертификата и заданный ненулевой ActorUserID подтверждающего пользователя.
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

// Validate требует ID сертификата и причину отклонения длиной 1–1000 символов.
func (in *RejectWorkProfileCertificationInput) Validate() error {

	if in == nil {
		return errors.New("reject work profile certification input is nil")
	}

	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}

	return validateText(in.RejectionReason, "rejection_reason", 1, 1000)
}

// Validate требует ID сертификата и причину отзыва длиной 1–1000 символов.
func (in *RevokeWorkProfileCertificationInput) Validate() error {

	if in == nil {
		return errors.New("revoke work profile certification input is nil")
	}

	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}

	return validateText(in.Reason, "reason", 1, 1000)
}

// Validate требует ненулевой запрос и нормализует Limit пакета непосредственно в in.
func (in *ExpireWorkProfileCertificationsInput) Validate() error {

	if in == nil {
		return errors.New("expire work profile certifications input is nil")
	}

	in.Limit, _ = normalizeLimitOffset(in.Limit, 0)
	return nil
}

// Validate проверяет ID рабочего профиля, заданные тип и статус сертификата
// и нормализует Limit и Offset в in.
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

// Validate требует ID профиля и навыка, причину 1–1000 символов, проверяет
// необязательный уровень 1–64 символа и срок ValidUntil строго в будущем.
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

// Validate требует ID назначения навыка и причину отзыва длиной 1–1000 символов.
func (in *RevokeWorkProfileSkillGrantInput) Validate() error {

	if in == nil {
		return errors.New("revoke work profile skill grant input is nil")
	}

	if err := validateUUID(in.ID, "id"); err != nil {
		return err
	}

	return validateText(in.Reason, "reason", 1, 1000)
}

// Validate требует ненулевой запрос и ID рабочего профиля для списка действующих навыков.
func (in *ListEffectiveWorkProfileSkillsInput) Validate() error {

	if in == nil {
		return errors.New("list effective work profile skills input is nil")
	}

	return validateUUID(in.WorkProfileID, "work_profile_id")
}

// Validate требует от 1 до MaxLimit уникальных ненулевых ID рабочих профилей.
// Исходный список не изменяет; повторный ID возвращает как ошибку.
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

// Validate требует ID рабочего профиля и непустой список уникальных ненулевых ID навыков.
// Наличие самих навыков не проверяет и in не изменяет.
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
