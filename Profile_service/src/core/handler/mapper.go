package handler

import (
	"time"

	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"profile/models"
)

func ToProtoPreferredContactMethod(value models.PreferredContactMethod) profilev1.PreferredContactMethod {
	switch value {
	case models.PreferredContactMethodEmail:
		return profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_EMAIL
	case models.PreferredContactMethodPhone:
		return profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_PHONE
	case models.PreferredContactMethodPush:
		return profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_PUSH
	default:
		return profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_UNSPECIFIED
	}
}

func FromProtoPreferredContactMethod(value profilev1.PreferredContactMethod) models.PreferredContactMethod {
	switch value {
	case profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_EMAIL:
		return models.PreferredContactMethodEmail
	case profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_PHONE:
		return models.PreferredContactMethodPhone
	case profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_PUSH:
		return models.PreferredContactMethodPush
	default:
		return ""
	}
}

func ToProtoWorkProfileStatus(value models.WorkProfileStatus) profilev1.WorkProfileStatus {
	switch value {
	case models.WorkProfileStatusActive:
		return profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_ACTIVE
	case models.WorkProfileStatusInactive:
		return profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_INACTIVE
	case models.WorkProfileStatusOnShift:
		return profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_ON_SHIFT
	case models.WorkProfileStatusOffShift:
		return profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_OFF_SHIFT
	case models.WorkProfileStatusSuspended:
		return profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_SUSPENDED
	default:
		return profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_UNSPECIFIED
	}
}

func FromProtoWorkProfileStatus(value profilev1.WorkProfileStatus) models.WorkProfileStatus {
	switch value {
	case profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_ACTIVE:
		return models.WorkProfileStatusActive
	case profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_INACTIVE:
		return models.WorkProfileStatusInactive
	case profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_ON_SHIFT:
		return models.WorkProfileStatusOnShift
	case profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_OFF_SHIFT:
		return models.WorkProfileStatusOffShift
	case profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_SUSPENDED:
		return models.WorkProfileStatusSuspended
	default:
		return ""
	}
}

func ToProtoCanJoinBrigadeReason(value models.CanJoinBrigadeReason) profilev1.CanJoinBrigadeReason {
	switch value {
	case models.CanJoinBrigadeReasonAllowed:
		return profilev1.CanJoinBrigadeReason_CAN_JOIN_BRIGADE_REASON_ALLOWED
	case models.CanJoinBrigadeReasonNoWorkProfile:
		return profilev1.CanJoinBrigadeReason_CAN_JOIN_BRIGADE_REASON_NO_WORK_PROFILE
	case models.CanJoinBrigadeReasonProfileInactive:
		return profilev1.CanJoinBrigadeReason_CAN_JOIN_BRIGADE_REASON_PROFILE_INACTIVE
	case models.CanJoinBrigadeReasonProfileSuspended:
		return profilev1.CanJoinBrigadeReason_CAN_JOIN_BRIGADE_REASON_PROFILE_SUSPENDED
	case models.CanJoinBrigadeReasonProfileOffShift:
		return profilev1.CanJoinBrigadeReason_CAN_JOIN_BRIGADE_REASON_PROFILE_OFF_SHIFT
	case models.CanJoinBrigadeReasonDepartmentMismatch:
		return profilev1.CanJoinBrigadeReason_CAN_JOIN_BRIGADE_REASON_DEPARTMENT_MISMATCH
	default:
		return profilev1.CanJoinBrigadeReason_CAN_JOIN_BRIGADE_REASON_UNSPECIFIED
	}
}

func ToProtoCertificationStatus(value models.CertificationStatus) profilev1.CertificationStatus {
	switch value {
	case models.CertificationStatusPending:
		return profilev1.CertificationStatus_CERTIFICATION_STATUS_PENDING
	case models.CertificationStatusVerified:
		return profilev1.CertificationStatus_CERTIFICATION_STATUS_VERIFIED
	case models.CertificationStatusRejected:
		return profilev1.CertificationStatus_CERTIFICATION_STATUS_REJECTED
	case models.CertificationStatusExpired:
		return profilev1.CertificationStatus_CERTIFICATION_STATUS_EXPIRED
	case models.CertificationStatusRevoked:
		return profilev1.CertificationStatus_CERTIFICATION_STATUS_REVOKED
	default:
		return profilev1.CertificationStatus_CERTIFICATION_STATUS_UNSPECIFIED
	}
}

func FromProtoCertificationStatus(value profilev1.CertificationStatus) models.CertificationStatus {
	switch value {
	case profilev1.CertificationStatus_CERTIFICATION_STATUS_PENDING:
		return models.CertificationStatusPending
	case profilev1.CertificationStatus_CERTIFICATION_STATUS_VERIFIED:
		return models.CertificationStatusVerified
	case profilev1.CertificationStatus_CERTIFICATION_STATUS_REJECTED:
		return models.CertificationStatusRejected
	case profilev1.CertificationStatus_CERTIFICATION_STATUS_EXPIRED:
		return models.CertificationStatusExpired
	case profilev1.CertificationStatus_CERTIFICATION_STATUS_REVOKED:
		return models.CertificationStatusRevoked
	default:
		return ""
	}
}

func ToProtoSkillGrantSourceType(value models.SkillGrantSourceType) profilev1.SkillGrantSourceType {
	switch value {
	case models.SkillGrantSourceTypeManual:
		return profilev1.SkillGrantSourceType_SKILL_GRANT_SOURCE_TYPE_MANUAL
	case models.SkillGrantSourceTypeCertification:
		return profilev1.SkillGrantSourceType_SKILL_GRANT_SOURCE_TYPE_CERTIFICATION
	default:
		return profilev1.SkillGrantSourceType_SKILL_GRANT_SOURCE_TYPE_UNSPECIFIED
	}
}

func FromProtoUserProfileSortBy(value profilev1.UserProfileSortBy) models.UserProfileSortBy {
	switch value {
	case profilev1.UserProfileSortBy_USER_PROFILE_SORT_BY_CREATED_AT:
		return models.UserProfileSortByCreatedAt
	case profilev1.UserProfileSortBy_USER_PROFILE_SORT_BY_UPDATED_AT:
		return models.UserProfileSortByUpdatedAt
	case profilev1.UserProfileSortBy_USER_PROFILE_SORT_BY_FULL_NAME:
		return models.UserProfileSortByFullName
	default:
		return ""
	}
}

func FromProtoWorkProfileSortBy(value profilev1.WorkProfileSortBy) models.WorkProfileSortBy {
	switch value {
	case profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_CREATED_AT:
		return models.WorkProfileSortByCreatedAt
	case profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_UPDATED_AT:
		return models.WorkProfileSortByUpdatedAt
	case profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_FULL_NAME:
		return models.WorkProfileSortByFullName
	case profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_POSITION:
		return models.WorkProfileSortByPosition
	case profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_STATUS:
		return models.WorkProfileSortByStatus
	case profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_EMPLOYEE_NUMBER:
		return models.WorkProfileSortByEmployeeNumber
	default:
		return ""
	}
}

func FromProtoSortOrder(value profilev1.SortOrder) models.SortOrder {
	switch value {
	case profilev1.SortOrder_SORT_ORDER_ASC:
		return models.SortOrderAsc
	case profilev1.SortOrder_SORT_ORDER_DESC:
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

func ToProtoTimestampPtr(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

func FromProtoTimestamp(t *timestamppb.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	value := t.AsTime()
	return &value
}

func uuidPtrToStringPtr(value *uuid.UUID) *string {
	if value == nil || *value == uuid.Nil {
		return nil
	}
	result := value.String()
	return &result
}

func stringPtrToUUIDPtr(value *string, field string) (*uuid.UUID, error) {
	if value == nil {
		return nil, nil
	}
	return parseOptionalUUID(*value, field)
}

func ToProtoUserProfile(profile *models.UserProfile) *profilev1.UserProfile {
	if profile == nil {
		return nil
	}
	return &profilev1.UserProfile{
		Id:                     profile.ID.String(),
		UserId:                 profile.UserID.String(),
		FullName:               profile.FullName,
		Phone:                  profile.Phone,
		AvatarFileId:           uuidPtrToStringPtr(profile.AvatarFileID),
		PreferredContactMethod: ToProtoPreferredContactMethod(profile.PreferredContactMethod),
		CreatedAt:              ToProtoTimestamp(profile.CreatedAt),
		UpdatedAt:              ToProtoTimestamp(profile.UpdatedAt),
	}
}

func ToProtoWorkProfile(profile *models.WorkProfile) *profilev1.WorkProfile {
	if profile == nil {
		return nil
	}
	return &profilev1.WorkProfile{
		Id:             profile.ID.String(),
		UserProfileId:  profile.UserProfileID.String(),
		DepartmentId:   profile.DepartmentID.String(),
		EmployeeNumber: profile.EmployeeNumber,
		Position:       profile.Position,
		Status:         ToProtoWorkProfileStatus(profile.Status),
		DeactivatedAt:  ToProtoTimestampPtr(profile.DeactivatedAt),
		CreatedAt:      ToProtoTimestamp(profile.CreatedAt),
		UpdatedAt:      ToProtoTimestamp(profile.UpdatedAt),
	}
}

func ToProtoWorkProfileDetails(details *models.WorkProfileDetails) *profilev1.WorkProfileDetails {
	if details == nil {
		return nil
	}
	return &profilev1.WorkProfileDetails{
		WorkProfile: ToProtoWorkProfile(details.WorkProfile),
		UserProfile: ToProtoUserProfile(details.UserProfile),
	}
}

func ToProtoWorkProfileStatusHistory(item *models.WorkProfileStatusHistory) *profilev1.WorkProfileStatusHistory {
	if item == nil {
		return nil
	}
	return &profilev1.WorkProfileStatusHistory{
		Id:              item.ID.String(),
		WorkProfileId:   item.WorkProfileID.String(),
		FromStatus:      workProfileStatusPtr(item.FromStatus),
		ToStatus:        ToProtoWorkProfileStatus(item.ToStatus),
		Reason:          item.Reason,
		ChangedByUserId: uuidPtrToStringPtr(item.ChangedByUserID),
		RequestId:       item.RequestID,
		CreatedAt:       ToProtoTimestamp(item.CreatedAt),
	}
}

func workProfileStatusPtr(value *models.WorkProfileStatus) *profilev1.WorkProfileStatus {
	if value == nil {
		return nil
	}
	result := ToProtoWorkProfileStatus(*value)
	return &result
}

func ToProtoCertificationType(item *models.CertificationType) *profilev1.CertificationType {
	if item == nil {
		return nil
	}
	return &profilev1.CertificationType{
		Id:                  item.ID.String(),
		Code:                item.Code,
		Name:                item.Name,
		Description:         item.Description,
		DefaultValidityDays: item.DefaultValidityDays,
		RequiresFile:        item.RequiresFile,
		Active:              item.Active,
		CreatedAt:           ToProtoTimestamp(item.CreatedAt),
		UpdatedAt:           ToProtoTimestamp(item.UpdatedAt),
	}
}

func ToProtoCertificationTypeSkill(item *models.CertificationTypeSkill) *profilev1.CertificationTypeSkill {
	if item == nil {
		return nil
	}
	return &profilev1.CertificationTypeSkill{
		Id:                  item.ID.String(),
		CertificationTypeId: item.CertificationTypeID.String(),
		SkillId:             item.SkillID.String(),
		ProficiencyLevel:    item.ProficiencyLevel,
		Active:              item.Active,
		CreatedAt:           ToProtoTimestamp(item.CreatedAt),
		UpdatedAt:           ToProtoTimestamp(item.UpdatedAt),
	}
}

func ToProtoWorkProfileCertification(item *models.WorkProfileCertification) *profilev1.WorkProfileCertification {
	if item == nil {
		return nil
	}
	return &profilev1.WorkProfileCertification{
		Id:                  item.ID.String(),
		WorkProfileId:       item.WorkProfileID.String(),
		CertificationTypeId: item.CertificationTypeID.String(),
		CertificateNumber:   item.CertificateNumber,
		Issuer:              item.Issuer,
		IssuedAt:            ToProtoTimestampPtr(item.IssuedAt),
		ExpiresAt:           ToProtoTimestampPtr(item.ExpiresAt),
		Status:              ToProtoCertificationStatus(item.Status),
		CertificateFileId:   uuidPtrToStringPtr(item.CertificateFileID),
		VerifiedByUserId:    uuidPtrToStringPtr(item.VerifiedByUserID),
		VerifiedAt:          ToProtoTimestampPtr(item.VerifiedAt),
		RejectionReason:     item.RejectionReason,
		CreatedAt:           ToProtoTimestamp(item.CreatedAt),
		UpdatedAt:           ToProtoTimestamp(item.UpdatedAt),
	}
}

func ToProtoWorkProfileSkillGrant(item *models.WorkProfileSkillGrant) *profilev1.WorkProfileSkillGrant {
	if item == nil {
		return nil
	}
	return &profilev1.WorkProfileSkillGrant{
		Id:               item.ID.String(),
		WorkProfileId:    item.WorkProfileID.String(),
		SkillId:          item.SkillID.String(),
		SourceType:       ToProtoSkillGrantSourceType(item.SourceType),
		SourceId:         uuidPtrToStringPtr(item.SourceID),
		ProficiencyLevel: item.ProficiencyLevel,
		ValidUntil:       ToProtoTimestampPtr(item.ValidUntil),
		Active:           item.Active,
		CreatedAt:        ToProtoTimestamp(item.CreatedAt),
		RevokedAt:        ToProtoTimestampPtr(item.RevokedAt),
	}
}

func toProtoUserProfiles(items []*models.UserProfile) []*profilev1.UserProfile {
	result := make([]*profilev1.UserProfile, 0, len(items))
	for _, item := range items {
		result = append(result, ToProtoUserProfile(item))
	}
	return result
}

func toProtoWorkProfileDetails(items []*models.WorkProfileDetails) []*profilev1.WorkProfileDetails {
	result := make([]*profilev1.WorkProfileDetails, 0, len(items))
	for _, item := range items {
		result = append(result, ToProtoWorkProfileDetails(item))
	}
	return result
}

func toProtoStatusHistory(items []*models.WorkProfileStatusHistory) []*profilev1.WorkProfileStatusHistory {
	result := make([]*profilev1.WorkProfileStatusHistory, 0, len(items))
	for _, item := range items {
		result = append(result, ToProtoWorkProfileStatusHistory(item))
	}
	return result
}

func toProtoCertificationTypes(items []*models.CertificationType) []*profilev1.CertificationType {
	result := make([]*profilev1.CertificationType, 0, len(items))
	for _, item := range items {
		result = append(result, ToProtoCertificationType(item))
	}
	return result
}

func toProtoCertificationTypeSkills(items []*models.CertificationTypeSkill) []*profilev1.CertificationTypeSkill {
	result := make([]*profilev1.CertificationTypeSkill, 0, len(items))
	for _, item := range items {
		result = append(result, ToProtoCertificationTypeSkill(item))
	}
	return result
}

func toProtoCertifications(items []*models.WorkProfileCertification) []*profilev1.WorkProfileCertification {
	result := make([]*profilev1.WorkProfileCertification, 0, len(items))
	for _, item := range items {
		result = append(result, ToProtoWorkProfileCertification(item))
	}
	return result
}

func toProtoSkillGrants(items []*models.WorkProfileSkillGrant) []*profilev1.WorkProfileSkillGrant {
	result := make([]*profilev1.WorkProfileSkillGrant, 0, len(items))
	for _, item := range items {
		result = append(result, ToProtoWorkProfileSkillGrant(item))
	}
	return result
}
