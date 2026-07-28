package handlers

import (
	"strings"

	"gateway/models"

	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func ToProtoPreferredContactMethod(value string) profilev1.PreferredContactMethod {
	switch normalizeEnum(value) {
	case "EMAIL":
		return profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_EMAIL
	case "PHONE":
		return profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_PHONE
	case "PUSH":
		return profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_PUSH
	default:
		return profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_UNSPECIFIED
	}
}

func FromProtoPreferredContactMethod(value profilev1.PreferredContactMethod) string {
	switch value {
	case profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_EMAIL:
		return string(models.PreferredContactMethodEmail)
	case profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_PHONE:
		return string(models.PreferredContactMethodPhone)
	case profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_PUSH:
		return string(models.PreferredContactMethodPush)
	default:
		return ""
	}
}

func ToProtoWorkProfileStatus(value string) profilev1.WorkProfileStatus {
	switch normalizeEnum(value) {
	case "ACTIVE":
		return profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_ACTIVE
	case "INACTIVE":
		return profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_INACTIVE
	case "ON_SHIFT":
		return profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_ON_SHIFT
	case "OFF_SHIFT":
		return profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_OFF_SHIFT
	case "SUSPENDED":
		return profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_SUSPENDED
	default:
		return profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_UNSPECIFIED
	}
}

func FromProtoWorkProfileStatus(value profilev1.WorkProfileStatus) string {
	switch value {
	case profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_ACTIVE:
		return string(models.WorkProfileStatusActive)
	case profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_INACTIVE:
		return string(models.WorkProfileStatusInactive)
	case profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_ON_SHIFT:
		return string(models.WorkProfileStatusOnShift)
	case profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_OFF_SHIFT:
		return string(models.WorkProfileStatusOffShift)
	case profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_SUSPENDED:
		return string(models.WorkProfileStatusSuspended)
	default:
		return ""
	}
}

func ToProtoCertificationStatus(value string) profilev1.CertificationStatus {
	switch normalizeEnum(value) {
	case "PENDING":
		return profilev1.CertificationStatus_CERTIFICATION_STATUS_PENDING
	case "VERIFIED":
		return profilev1.CertificationStatus_CERTIFICATION_STATUS_VERIFIED
	case "REJECTED":
		return profilev1.CertificationStatus_CERTIFICATION_STATUS_REJECTED
	case "EXPIRED":
		return profilev1.CertificationStatus_CERTIFICATION_STATUS_EXPIRED
	case "REVOKED":
		return profilev1.CertificationStatus_CERTIFICATION_STATUS_REVOKED
	default:
		return profilev1.CertificationStatus_CERTIFICATION_STATUS_UNSPECIFIED
	}
}

func FromProtoCertificationStatus(value profilev1.CertificationStatus) string {
	switch value {
	case profilev1.CertificationStatus_CERTIFICATION_STATUS_PENDING:
		return string(models.CertificationStatusPending)
	case profilev1.CertificationStatus_CERTIFICATION_STATUS_VERIFIED:
		return string(models.CertificationStatusVerified)
	case profilev1.CertificationStatus_CERTIFICATION_STATUS_REJECTED:
		return string(models.CertificationStatusRejected)
	case profilev1.CertificationStatus_CERTIFICATION_STATUS_EXPIRED:
		return string(models.CertificationStatusExpired)
	case profilev1.CertificationStatus_CERTIFICATION_STATUS_REVOKED:
		return string(models.CertificationStatusRevoked)
	default:
		return ""
	}
}

func FromProtoSkillGrantSourceType(value profilev1.SkillGrantSourceType) string {
	switch value {
	case profilev1.SkillGrantSourceType_SKILL_GRANT_SOURCE_TYPE_MANUAL:
		return string(models.SkillGrantSourceTypeManual)
	case profilev1.SkillGrantSourceType_SKILL_GRANT_SOURCE_TYPE_CERTIFICATION:
		return string(models.SkillGrantSourceTypeCertification)
	default:
		return ""
	}
}

func FromProtoCanJoinBrigadeReason(value profilev1.CanJoinBrigadeReason) string {
	switch value {
	case profilev1.CanJoinBrigadeReason_CAN_JOIN_BRIGADE_REASON_ALLOWED:
		return string(models.CanJoinBrigadeReasonAllowed)
	case profilev1.CanJoinBrigadeReason_CAN_JOIN_BRIGADE_REASON_NO_WORK_PROFILE:
		return string(models.CanJoinBrigadeReasonNoWorkProfile)
	case profilev1.CanJoinBrigadeReason_CAN_JOIN_BRIGADE_REASON_PROFILE_INACTIVE:
		return string(models.CanJoinBrigadeReasonProfileInactive)
	case profilev1.CanJoinBrigadeReason_CAN_JOIN_BRIGADE_REASON_PROFILE_SUSPENDED:
		return string(models.CanJoinBrigadeReasonProfileSuspended)
	case profilev1.CanJoinBrigadeReason_CAN_JOIN_BRIGADE_REASON_PROFILE_OFF_SHIFT:
		return string(models.CanJoinBrigadeReasonProfileOffShift)
	case profilev1.CanJoinBrigadeReason_CAN_JOIN_BRIGADE_REASON_DEPARTMENT_MISMATCH:
		return string(models.CanJoinBrigadeReasonDepartmentMismatch)
	default:
		return ""
	}
}

func ToProtoUserProfileSortBy(value string) profilev1.UserProfileSortBy {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "created_at":
		return profilev1.UserProfileSortBy_USER_PROFILE_SORT_BY_CREATED_AT
	case "updated_at":
		return profilev1.UserProfileSortBy_USER_PROFILE_SORT_BY_UPDATED_AT
	case "full_name":
		return profilev1.UserProfileSortBy_USER_PROFILE_SORT_BY_FULL_NAME
	default:
		return profilev1.UserProfileSortBy_USER_PROFILE_SORT_BY_UNSPECIFIED
	}
}

func ToProtoWorkProfileSortBy(value string) profilev1.WorkProfileSortBy {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "created_at":
		return profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_CREATED_AT
	case "updated_at":
		return profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_UPDATED_AT
	case "full_name":
		return profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_FULL_NAME
	case "position":
		return profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_POSITION
	case "status":
		return profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_STATUS
	case "employee_number":
		return profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_EMPLOYEE_NUMBER
	default:
		return profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_UNSPECIFIED
	}
}

func ToProtoProfileSortOrder(value string) profilev1.SortOrder {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "asc":
		return profilev1.SortOrder_SORT_ORDER_ASC
	case "desc":
		return profilev1.SortOrder_SORT_ORDER_DESC
	default:
		return profilev1.SortOrder_SORT_ORDER_UNSPECIFIED
	}
}

func ToOptionalProtoTimestamp(value *string) (*timestamppb.Timestamp, bool) {
	if value == nil {
		return nil, true
	}
	ts, err := ToProtoTimestamp(*value)
	if err != nil {
		return nil, false
	}
	return ts, true
}

func FromProtoUserProfile(item *profilev1.UserProfile) *models.UserProfile {
	if item == nil {
		return nil
	}
	return &models.UserProfile{
		ID:                     item.GetId(),
		UserID:                 item.GetUserId(),
		FullName:               item.GetFullName(),
		Phone:                  item.GetPhone(),
		AvatarFileID:           item.GetAvatarFileId(),
		PreferredContactMethod: FromProtoPreferredContactMethod(item.GetPreferredContactMethod()),
		CreatedAtUnix:          timestampUnix(item.GetCreatedAt()),
		UpdatedAtUnix:          timestampUnix(item.GetUpdatedAt()),
	}
}

func FromProtoUserProfiles(items []*profilev1.UserProfile) []*models.UserProfile {
	result := make([]*models.UserProfile, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoUserProfile(item))
	}
	return result
}

func FromProtoWorkProfile(item *profilev1.WorkProfile) *models.WorkProfile {
	if item == nil {
		return nil
	}
	return &models.WorkProfile{
		ID:              item.GetId(),
		UserProfileID:   item.GetUserProfileId(),
		DepartmentID:    item.GetDepartmentId(),
		EmployeeNumber:  item.GetEmployeeNumber(),
		Position:        item.GetPosition(),
		Status:          FromProtoWorkProfileStatus(item.GetStatus()),
		DeactivatedUnix: timestampUnix(item.GetDeactivatedAt()),
		CreatedAtUnix:   timestampUnix(item.GetCreatedAt()),
		UpdatedAtUnix:   timestampUnix(item.GetUpdatedAt()),
	}
}

func FromProtoWorkProfileDetails(item *profilev1.WorkProfileDetails) *models.WorkProfileDetails {
	if item == nil {
		return nil
	}
	return &models.WorkProfileDetails{
		WorkProfile: FromProtoWorkProfile(item.GetWorkProfile()),
		UserProfile: FromProtoUserProfile(item.GetUserProfile()),
	}
}

func FromProtoWorkProfileDetailsItems(items []*profilev1.WorkProfileDetails) []*models.WorkProfileDetails {
	result := make([]*models.WorkProfileDetails, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoWorkProfileDetails(item))
	}
	return result
}

func FromProtoWorkProfileStatusHistory(item *profilev1.WorkProfileStatusHistory) *models.WorkProfileStatusHistory {
	if item == nil {
		return nil
	}
	return &models.WorkProfileStatusHistory{
		ID:              item.GetId(),
		WorkProfileID:   item.GetWorkProfileId(),
		FromStatus:      FromProtoWorkProfileStatus(item.GetFromStatus()),
		ToStatus:        FromProtoWorkProfileStatus(item.GetToStatus()),
		Reason:          item.GetReason(),
		ChangedByUserID: item.GetChangedByUserId(),
		RequestID:       item.GetRequestId(),
		CreatedAtUnix:   timestampUnix(item.GetCreatedAt()),
	}
}

func FromProtoWorkProfileStatusHistoryItems(items []*profilev1.WorkProfileStatusHistory) []*models.WorkProfileStatusHistory {
	result := make([]*models.WorkProfileStatusHistory, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoWorkProfileStatusHistory(item))
	}
	return result
}

func FromProtoCertificationType(item *profilev1.CertificationType) *models.CertificationType {
	if item == nil {
		return nil
	}
	return &models.CertificationType{
		ID:                  item.GetId(),
		Code:                item.GetCode(),
		Name:                item.GetName(),
		Description:         item.GetDescription(),
		DefaultValidityDays: item.GetDefaultValidityDays(),
		RequiresFile:        item.GetRequiresFile(),
		Active:              item.GetActive(),
		CreatedAtUnix:       timestampUnix(item.GetCreatedAt()),
		UpdatedAtUnix:       timestampUnix(item.GetUpdatedAt()),
	}
}

func FromProtoCertificationTypes(items []*profilev1.CertificationType) []*models.CertificationType {
	result := make([]*models.CertificationType, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoCertificationType(item))
	}
	return result
}

func FromProtoCertificationTypeSkill(item *profilev1.CertificationTypeSkill) *models.CertificationTypeSkill {
	if item == nil {
		return nil
	}
	return &models.CertificationTypeSkill{
		ID:                  item.GetId(),
		CertificationTypeID: item.GetCertificationTypeId(),
		SkillID:             item.GetSkillId(),
		ProficiencyLevel:    item.GetProficiencyLevel(),
		Active:              item.GetActive(),
		CreatedAtUnix:       timestampUnix(item.GetCreatedAt()),
		UpdatedAtUnix:       timestampUnix(item.GetUpdatedAt()),
	}
}

func FromProtoCertificationTypeSkills(items []*profilev1.CertificationTypeSkill) []*models.CertificationTypeSkill {
	result := make([]*models.CertificationTypeSkill, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoCertificationTypeSkill(item))
	}
	return result
}

func FromProtoWorkProfileCertification(item *profilev1.WorkProfileCertification) *models.WorkProfileCertification {
	if item == nil {
		return nil
	}
	return &models.WorkProfileCertification{
		ID:                  item.GetId(),
		WorkProfileID:       item.GetWorkProfileId(),
		CertificationTypeID: item.GetCertificationTypeId(),
		CertificateNumber:   item.GetCertificateNumber(),
		Issuer:              item.GetIssuer(),
		IssuedAtUnix:        timestampUnix(item.GetIssuedAt()),
		ExpiresAtUnix:       timestampUnix(item.GetExpiresAt()),
		Status:              FromProtoCertificationStatus(item.GetStatus()),
		CertificateFileID:   item.GetCertificateFileId(),
		VerifiedByUserID:    item.GetVerifiedByUserId(),
		VerifiedAtUnix:      timestampUnix(item.GetVerifiedAt()),
		RejectionReason:     item.GetRejectionReason(),
		CreatedAtUnix:       timestampUnix(item.GetCreatedAt()),
		UpdatedAtUnix:       timestampUnix(item.GetUpdatedAt()),
	}
}

func FromProtoWorkProfileCertifications(items []*profilev1.WorkProfileCertification) []*models.WorkProfileCertification {
	result := make([]*models.WorkProfileCertification, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoWorkProfileCertification(item))
	}
	return result
}

func FromProtoWorkProfileSkillGrant(item *profilev1.WorkProfileSkillGrant) *models.WorkProfileSkillGrant {
	if item == nil {
		return nil
	}
	return &models.WorkProfileSkillGrant{
		ID:               item.GetId(),
		WorkProfileID:    item.GetWorkProfileId(),
		SkillID:          item.GetSkillId(),
		SourceType:       FromProtoSkillGrantSourceType(item.GetSourceType()),
		SourceID:         item.GetSourceId(),
		ProficiencyLevel: item.GetProficiencyLevel(),
		ValidUntilUnix:   timestampUnix(item.GetValidUntil()),
		Active:           item.GetActive(),
		CreatedAtUnix:    timestampUnix(item.GetCreatedAt()),
		RevokedAtUnix:    timestampUnix(item.GetRevokedAt()),
	}
}

func FromProtoWorkProfileSkillGrants(items []*profilev1.WorkProfileSkillGrant) []*models.WorkProfileSkillGrant {
	result := make([]*models.WorkProfileSkillGrant, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoWorkProfileSkillGrant(item))
	}
	return result
}

func FromProtoEffectiveWorkProfileSkills(item *profilev1.EffectiveWorkProfileSkills) *models.EffectiveWorkProfileSkills {
	if item == nil {
		return nil
	}
	return &models.EffectiveWorkProfileSkills{
		WorkProfileID: item.GetWorkProfileId(),
		SkillGrants:   FromProtoWorkProfileSkillGrants(item.GetSkillGrants()),
	}
}

func FromProtoEffectiveWorkProfileSkillsItems(items []*profilev1.EffectiveWorkProfileSkills) []*models.EffectiveWorkProfileSkills {
	result := make([]*models.EffectiveWorkProfileSkills, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoEffectiveWorkProfileSkills(item))
	}
	return result
}
