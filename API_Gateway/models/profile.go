package models

// PreferredContactMethod описывает доменную модель.
type PreferredContactMethod string

const (
	PreferredContactMethodEmail PreferredContactMethod = "EMAIL"
	PreferredContactMethodPhone PreferredContactMethod = "PHONE"
	PreferredContactMethodPush  PreferredContactMethod = "PUSH"
)

// WorkProfileStatus задаёт допустимое состояние модели.
type WorkProfileStatus string

const (
	WorkProfileStatusActive    WorkProfileStatus = "ACTIVE"
	WorkProfileStatusInactive  WorkProfileStatus = "INACTIVE"
	WorkProfileStatusOnShift   WorkProfileStatus = "ON_SHIFT"
	WorkProfileStatusOffShift  WorkProfileStatus = "OFF_SHIFT"
	WorkProfileStatusSuspended WorkProfileStatus = "SUSPENDED"
)

// CertificationStatus задаёт допустимое состояние модели.
type CertificationStatus string

const (
	CertificationStatusPending  CertificationStatus = "PENDING"
	CertificationStatusVerified CertificationStatus = "VERIFIED"
	CertificationStatusRejected CertificationStatus = "REJECTED"
	CertificationStatusExpired  CertificationStatus = "EXPIRED"
	CertificationStatusRevoked  CertificationStatus = "REVOKED"
)

// SkillGrantSourceType задаёт тип доменной модели.
type SkillGrantSourceType string

const (
	SkillGrantSourceTypeManual        SkillGrantSourceType = "MANUAL"
	SkillGrantSourceTypeCertification SkillGrantSourceType = "CERTIFICATION"
)

// CanJoinBrigadeReason описывает доменную модель.
type CanJoinBrigadeReason string

const (
	CanJoinBrigadeReasonAllowed            CanJoinBrigadeReason = "ALLOWED"
	CanJoinBrigadeReasonNoWorkProfile      CanJoinBrigadeReason = "NO_WORK_PROFILE"
	CanJoinBrigadeReasonProfileInactive    CanJoinBrigadeReason = "PROFILE_INACTIVE"
	CanJoinBrigadeReasonProfileSuspended   CanJoinBrigadeReason = "PROFILE_SUSPENDED"
	CanJoinBrigadeReasonProfileOffShift    CanJoinBrigadeReason = "PROFILE_OFF_SHIFT"
	CanJoinBrigadeReasonDepartmentMismatch CanJoinBrigadeReason = "DEPARTMENT_MISMATCH"
)

// UserProfile описывает пользовательский профиль сотрудника.
type UserProfile struct {
	ID                     string `json:"id"`
	UserID                 string `json:"user_id"`
	FullName               string `json:"full_name"`
	Phone                  string `json:"phone,omitempty"`
	AvatarFileID           string `json:"avatar_file_id,omitempty"`
	PreferredContactMethod string `json:"preferred_contact_method"`
	CreatedAtUnix          int64  `json:"created_at"`
	UpdatedAtUnix          int64  `json:"updated_at"`
}

// WorkProfile описывает рабочий профиль сотрудника.
type WorkProfile struct {
	ID              string `json:"id"`
	UserProfileID   string `json:"user_profile_id"`
	DepartmentID    string `json:"department_id"`
	EmployeeNumber  string `json:"employee_number,omitempty"`
	Position        string `json:"position"`
	Status          string `json:"status"`
	DeactivatedUnix int64  `json:"deactivated_at,omitempty"`
	CreatedAtUnix   int64  `json:"created_at"`
	UpdatedAtUnix   int64  `json:"updated_at"`
}

// WorkProfileDetails объединяет рабочий профиль и связанные с ним данные.
type WorkProfileDetails struct {
	WorkProfile *WorkProfile `json:"work_profile"`
	UserProfile *UserProfile `json:"user_profile"`
}

// WorkProfileStatusHistory описывает доменную модель.
type WorkProfileStatusHistory struct {
	ID              string `json:"id"`
	WorkProfileID   string `json:"work_profile_id"`
	FromStatus      string `json:"from_status,omitempty"`
	ToStatus        string `json:"to_status"`
	Reason          string `json:"reason"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	CreatedAtUnix   int64  `json:"created_at"`
}

// CertificationType задаёт тип доменной модели.
type CertificationType struct {
	ID                  string `json:"id"`
	Code                string `json:"code"`
	Name                string `json:"name"`
	Description         string `json:"description,omitempty"`
	DefaultValidityDays int32  `json:"default_validity_days,omitempty"`
	RequiresFile        bool   `json:"requires_file"`
	Active              bool   `json:"active"`
	CreatedAtUnix       int64  `json:"created_at"`
	UpdatedAtUnix       int64  `json:"updated_at"`
}

// CertificationTypeSkill описывает доменную модель.
type CertificationTypeSkill struct {
	ID                  string `json:"id"`
	CertificationTypeID string `json:"certification_type_id"`
	SkillID             string `json:"skill_id"`
	ProficiencyLevel    string `json:"proficiency_level,omitempty"`
	Active              bool   `json:"active"`
	CreatedAtUnix       int64  `json:"created_at"`
	UpdatedAtUnix       int64  `json:"updated_at"`
}

// WorkProfileCertification описывает доменную модель.
type WorkProfileCertification struct {
	ID                  string `json:"id"`
	WorkProfileID       string `json:"work_profile_id"`
	CertificationTypeID string `json:"certification_type_id"`
	CertificateNumber   string `json:"certificate_number,omitempty"`
	Issuer              string `json:"issuer,omitempty"`
	IssuedAtUnix        int64  `json:"issued_at,omitempty"`
	ExpiresAtUnix       int64  `json:"expires_at,omitempty"`
	Status              string `json:"status"`
	CertificateFileID   string `json:"certificate_file_id,omitempty"`
	VerifiedByUserID    string `json:"verified_by_user_id,omitempty"`
	VerifiedAtUnix      int64  `json:"verified_at,omitempty"`
	RejectionReason     string `json:"rejection_reason,omitempty"`
	CreatedAtUnix       int64  `json:"created_at"`
	UpdatedAtUnix       int64  `json:"updated_at"`
}

// WorkProfileSkillGrant описывает доменную модель.
type WorkProfileSkillGrant struct {
	ID               string `json:"id"`
	WorkProfileID    string `json:"work_profile_id"`
	SkillID          string `json:"skill_id"`
	SourceType       string `json:"source_type"`
	SourceID         string `json:"source_id,omitempty"`
	ProficiencyLevel string `json:"proficiency_level,omitempty"`
	ValidUntilUnix   int64  `json:"valid_until,omitempty"`
	Active           bool   `json:"active"`
	CreatedAtUnix    int64  `json:"created_at"`
	RevokedAtUnix    int64  `json:"revoked_at,omitempty"`
}

// EffectiveWorkProfileSkills описывает доменную модель.
type EffectiveWorkProfileSkills struct {
	WorkProfileID string                   `json:"work_profile_id"`
	SkillGrants   []*WorkProfileSkillGrant `json:"skill_grants"`
}

// CreateUserProfileRequest содержит параметры API-запроса.
type CreateUserProfileRequest struct {
	UserID                 string  `json:"user_id" binding:"required,uuid"`
	FullName               string  `json:"full_name" binding:"required,min=2,max=255"`
	Phone                  *string `json:"phone,omitempty" binding:"omitempty,max=32"`
	AvatarFileID           *string `json:"avatar_file_id,omitempty" binding:"omitempty,uuid"`
	PreferredContactMethod string  `json:"preferred_contact_method" binding:"required,oneof=email phone push"`
}

// GetUserProfileByIDRequest содержит параметры API-запроса.
type GetUserProfileByIDRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

// GetUserProfileByUserIDRequest содержит параметры API-запроса.
type GetUserProfileByUserIDRequest struct {
	UserID string `json:"user_id" binding:"required,uuid"`
}

// ListUserProfilesRequest содержит параметры API-запроса.
type ListUserProfilesRequest struct {
	Query     *string `json:"query,omitempty" binding:"omitempty,max=255"`
	Limit     *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset    *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
	SortBy    *string `json:"sort_by,omitempty" binding:"omitempty,oneof=created_at updated_at full_name"`
	SortOrder *string `json:"sort_order,omitempty" binding:"omitempty,oneof=asc desc"`
}

// UpdateUserProfileRequest содержит параметры API-запроса.
type UpdateUserProfileRequest struct {
	ID                     string  `json:"id" binding:"required,uuid"`
	FullName               *string `json:"full_name,omitempty" binding:"omitempty,min=2,max=255"`
	Phone                  *string `json:"phone,omitempty" binding:"omitempty,max=32"`
	ClearPhone             *bool   `json:"clear_phone,omitempty"`
	AvatarFileID           *string `json:"avatar_file_id,omitempty" binding:"omitempty,uuid"`
	ClearAvatarFileID      *bool   `json:"clear_avatar_file_id,omitempty"`
	PreferredContactMethod *string `json:"preferred_contact_method,omitempty" binding:"omitempty,oneof=email phone push"`
}

// CreateWorkProfileRequest содержит параметры API-запроса.
type CreateWorkProfileRequest struct {
	UserProfileID  string  `json:"user_profile_id" binding:"required,uuid"`
	DepartmentID   string  `json:"department_id" binding:"required,uuid"`
	EmployeeNumber *string `json:"employee_number,omitempty" binding:"omitempty,max=64"`
	Position       string  `json:"position" binding:"required,min=2,max=255"`
}

// GetWorkProfileByIDRequest содержит параметры API-запроса.
type GetWorkProfileByIDRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

// GetWorkProfileByUserIDRequest содержит параметры API-запроса.
type GetWorkProfileByUserIDRequest struct {
	UserID string `json:"user_id" binding:"required,uuid"`
}

// ListWorkProfilesRequest содержит параметры API-запроса.
type ListWorkProfilesRequest struct {
	DepartmentID *string `json:"department_id,omitempty" binding:"omitempty,uuid"`
	Status       *string `json:"status,omitempty" binding:"omitempty,oneof=active inactive on_shift off_shift suspended"`
	Query        *string `json:"query,omitempty" binding:"omitempty,max=255"`
	Limit        *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset       *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
	SortBy       *string `json:"sort_by,omitempty" binding:"omitempty,oneof=created_at updated_at full_name position status employee_number"`
	SortOrder    *string `json:"sort_order,omitempty" binding:"omitempty,oneof=asc desc"`
}

// UpdateWorkProfileRequest содержит параметры API-запроса.
type UpdateWorkProfileRequest struct {
	ID                  string  `json:"id" binding:"required,uuid"`
	EmployeeNumber      *string `json:"employee_number,omitempty" binding:"omitempty,max=64"`
	ClearEmployeeNumber *bool   `json:"clear_employee_number,omitempty"`
	Position            *string `json:"position,omitempty" binding:"omitempty,min=2,max=255"`
}

// DeactivateWorkProfileRequest содержит параметры API-запроса.
type DeactivateWorkProfileRequest struct {
	ID     string `json:"id" binding:"required,uuid"`
	Reason string `json:"reason" binding:"required,max=1000"`
}

// ChangeWorkProfileDepartmentRequest содержит параметры API-запроса.
type ChangeWorkProfileDepartmentRequest struct {
	ID           string `json:"id" binding:"required,uuid"`
	DepartmentID string `json:"department_id" binding:"required,uuid"`
	Reason       string `json:"reason" binding:"required,max=1000"`
}

// SetWorkProfileStatusRequest содержит параметры API-запроса.
type SetWorkProfileStatusRequest struct {
	ID     string `json:"id" binding:"required,uuid"`
	Status string `json:"status" binding:"required,oneof=active inactive on_shift off_shift suspended"`
	Reason string `json:"reason" binding:"omitempty,max=1000"`
}

// WorkProfileStatusHistoryRequest содержит параметры API-запроса.
type WorkProfileStatusHistoryRequest struct {
	WorkProfileID string `json:"work_profile_id" binding:"required,uuid"`
	Limit         *int32 `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset        *int32 `json:"offset,omitempty" binding:"omitempty,min=0"`
}

// ResolveWorkingDepartmentRequest содержит параметры API-запроса.
type ResolveWorkingDepartmentRequest struct {
	UserID string `json:"user_id" binding:"required,uuid"`
}

// CheckProfileCanJoinBrigadeRequest содержит параметры API-запроса.
type CheckProfileCanJoinBrigadeRequest struct {
	UserID              *string `json:"user_id,omitempty" binding:"omitempty,uuid"`
	WorkProfileID       *string `json:"work_profile_id,omitempty" binding:"omitempty,uuid"`
	BrigadeDepartmentID string  `json:"brigade_department_id" binding:"required,uuid"`
}

// CreateCertificationTypeRequest содержит параметры API-запроса.
type CreateCertificationTypeRequest struct {
	Code                string  `json:"code" binding:"required,min=2,max=100"`
	Name                string  `json:"name" binding:"required,min=2,max=255"`
	Description         *string `json:"description,omitempty" binding:"omitempty,max=1000"`
	DefaultValidityDays *int32  `json:"default_validity_days,omitempty" binding:"omitempty,min=1"`
	RequiresFile        bool    `json:"requires_file"`
}

// UpdateCertificationTypeRequest содержит параметры API-запроса.
type UpdateCertificationTypeRequest struct {
	ID                  string  `json:"id" binding:"required,uuid"`
	Code                *string `json:"code,omitempty" binding:"omitempty,min=2,max=100"`
	Name                *string `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	Description         *string `json:"description,omitempty" binding:"omitempty,max=1000"`
	ClearDescription    *bool   `json:"clear_description,omitempty"`
	DefaultValidityDays *int32  `json:"default_validity_days,omitempty" binding:"omitempty,min=1"`
	ClearValidityDays   *bool   `json:"clear_validity_days,omitempty"`
	RequiresFile        *bool   `json:"requires_file,omitempty"`
	Active              *bool   `json:"active,omitempty"`
}

// ListCertificationTypesRequest содержит параметры API-запроса.
type ListCertificationTypesRequest struct {
	Active *bool   `json:"active,omitempty"`
	Query  *string `json:"query,omitempty" binding:"omitempty,max=255"`
	Limit  *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
}

// CertificationTypeSkillRequest содержит параметры API-запроса.
type CertificationTypeSkillRequest struct {
	CertificationTypeID string  `json:"certification_type_id" binding:"required,uuid"`
	SkillID             string  `json:"skill_id" binding:"required,uuid"`
	ProficiencyLevel    *string `json:"proficiency_level,omitempty" binding:"omitempty,max=100"`
}

// ListCertificationTypeSkillsRequest содержит параметры API-запроса.
type ListCertificationTypeSkillsRequest struct {
	CertificationTypeID string `json:"certification_type_id" binding:"required,uuid"`
	ActiveOnly          bool   `json:"active_only"`
}

// UploadWorkProfileCertificationRequest содержит параметры API-запроса.
type UploadWorkProfileCertificationRequest struct {
	WorkProfileID       string  `json:"work_profile_id" binding:"required,uuid"`
	CertificationTypeID string  `json:"certification_type_id" binding:"required,uuid"`
	CertificateNumber   *string `json:"certificate_number,omitempty" binding:"omitempty,max=100"`
	Issuer              *string `json:"issuer,omitempty" binding:"omitempty,max=255"`
	IssuedAt            *string `json:"issued_at,omitempty" binding:"omitempty,datetime=2006-01-02T15:04:05Z"`
	ExpiresAt           *string `json:"expires_at,omitempty" binding:"omitempty,datetime=2006-01-02T15:04:05Z"`
	CertificateFileID   *string `json:"certificate_file_id,omitempty" binding:"omitempty,uuid"`
}

// CertificationIDRequest содержит параметры API-запроса.
type CertificationIDRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

// RejectWorkProfileCertificationRequest содержит параметры API-запроса.
type RejectWorkProfileCertificationRequest struct {
	ID              string `json:"id" binding:"required,uuid"`
	RejectionReason string `json:"rejection_reason" binding:"required,max=1000"`
}

// RevokeWorkProfileCertificationRequest содержит параметры API-запроса.
type RevokeWorkProfileCertificationRequest struct {
	ID     string `json:"id" binding:"required,uuid"`
	Reason string `json:"reason" binding:"required,max=1000"`
}

// ExpireWorkProfileCertificationsRequest содержит параметры API-запроса.
type ExpireWorkProfileCertificationsRequest struct {
	Limit *int32 `json:"limit,omitempty" binding:"omitempty,min=1,max=500"`
}

// ListWorkProfileCertificationsRequest содержит параметры API-запроса.
type ListWorkProfileCertificationsRequest struct {
	WorkProfileID       string  `json:"work_profile_id" binding:"required,uuid"`
	CertificationTypeID *string `json:"certification_type_id,omitempty" binding:"omitempty,uuid"`
	Status              *string `json:"status,omitempty" binding:"omitempty,oneof=pending verified rejected expired revoked"`
	Limit               *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset              *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
}

// GrantManualWorkProfileSkillRequest содержит параметры API-запроса.
type GrantManualWorkProfileSkillRequest struct {
	WorkProfileID    string  `json:"work_profile_id" binding:"required,uuid"`
	SkillID          string  `json:"skill_id" binding:"required,uuid"`
	ProficiencyLevel *string `json:"proficiency_level,omitempty" binding:"omitempty,max=100"`
	ValidUntil       *string `json:"valid_until,omitempty" binding:"omitempty,datetime=2006-01-02T15:04:05Z"`
	Reason           string  `json:"reason" binding:"required,max=1000"`
}

// RevokeWorkProfileSkillGrantRequest содержит параметры API-запроса.
type RevokeWorkProfileSkillGrantRequest struct {
	ID     string `json:"id" binding:"required,uuid"`
	Reason string `json:"reason" binding:"required,max=1000"`
}

// ListEffectiveWorkProfileSkillsRequest содержит параметры API-запроса.
type ListEffectiveWorkProfileSkillsRequest struct {
	WorkProfileID string `json:"work_profile_id" binding:"required,uuid"`
}

// BatchListEffectiveWorkProfileSkillsRequest содержит параметры API-запроса.
type BatchListEffectiveWorkProfileSkillsRequest struct {
	WorkProfileIDs []string `json:"work_profile_ids" binding:"required,min=1,dive,uuid"`
}

// CheckWorkProfileHasSkillsRequest содержит параметры API-запроса.
type CheckWorkProfileHasSkillsRequest struct {
	WorkProfileID    string   `json:"work_profile_id" binding:"required,uuid"`
	RequiredSkillIDs []string `json:"required_skill_ids" binding:"required,min=1,dive,uuid"`
}

// UserProfileResponse содержит данные API-ответа.
type UserProfileResponse struct {
	UserProfile *UserProfile `json:"user_profile"`
}

// ListUserProfilesResponse содержит данные API-ответа.
type ListUserProfilesResponse struct {
	UserProfiles []*UserProfile `json:"user_profiles"`
	Total        int64          `json:"total"`
}

// WorkProfileDetailsResponse содержит данные API-ответа.
type WorkProfileDetailsResponse struct {
	Details *WorkProfileDetails `json:"details"`
}

// ListWorkProfilesResponse содержит данные API-ответа.
type ListWorkProfilesResponse struct {
	WorkProfiles []*WorkProfileDetails `json:"work_profiles"`
	Total        int64                 `json:"total"`
}

// WorkProfileStatusHistoryResponse содержит данные API-ответа.
type WorkProfileStatusHistoryResponse struct {
	History []*WorkProfileStatusHistory `json:"history"`
	Total   int64                       `json:"total"`
}

// ResolveWorkingDepartmentResponse содержит данные API-ответа.
type ResolveWorkingDepartmentResponse struct {
	UserProfileID     string `json:"user_profile_id"`
	WorkProfileID     string `json:"work_profile_id"`
	UserID            string `json:"user_id"`
	DepartmentID      string `json:"department_id"`
	WorkProfileStatus string `json:"work_profile_status"`
	CanOperate        bool   `json:"can_operate"`
}

// CheckProfileCanJoinBrigadeResponse содержит данные API-ответа.
type CheckProfileCanJoinBrigadeResponse struct {
	UserProfileID string `json:"user_profile_id"`
	WorkProfileID string `json:"work_profile_id"`
	UserID        string `json:"user_id"`
	DepartmentID  string `json:"department_id"`
	Allowed       bool   `json:"allowed"`
	Reason        string `json:"reason"`
}

// CertificationTypeResponse содержит данные API-ответа.
type CertificationTypeResponse struct {
	CertificationType *CertificationType `json:"certification_type"`
}

// ListCertificationTypesResponse содержит данные API-ответа.
type ListCertificationTypesResponse struct {
	CertificationTypes []*CertificationType `json:"certification_types"`
	Total              int64                `json:"total"`
}

// CertificationTypeSkillResponse содержит данные API-ответа.
type CertificationTypeSkillResponse struct {
	CertificationTypeSkill *CertificationTypeSkill `json:"certification_type_skill"`
}

// RemoveCertificationTypeSkillResponse содержит данные API-ответа.
type RemoveCertificationTypeSkillResponse struct {
	Success bool `json:"success"`
}

// ListCertificationTypeSkillsResponse содержит данные API-ответа.
type ListCertificationTypeSkillsResponse struct {
	Skills []*CertificationTypeSkill `json:"skills"`
}

// WorkProfileCertificationResponse содержит данные API-ответа.
type WorkProfileCertificationResponse struct {
	Certification *WorkProfileCertification `json:"certification"`
}

// VerifyWorkProfileCertificationResponse содержит данные API-ответа.
type VerifyWorkProfileCertificationResponse struct {
	Certification *WorkProfileCertification `json:"certification"`
	SkillGrants   []*WorkProfileSkillGrant  `json:"skill_grants"`
}

// RevokeWorkProfileCertificationResponse содержит данные API-ответа.
type RevokeWorkProfileCertificationResponse struct {
	Certification *WorkProfileCertification `json:"certification"`
	RevokedGrants []*WorkProfileSkillGrant  `json:"revoked_grants"`
}

// ExpireWorkProfileCertificationsResponse содержит данные API-ответа.
type ExpireWorkProfileCertificationsResponse struct {
	ExpiredCertifications []*WorkProfileCertification `json:"expired_certifications"`
	RevokedGrants         []*WorkProfileSkillGrant    `json:"revoked_grants"`
}

// ListWorkProfileCertificationsResponse содержит данные API-ответа.
type ListWorkProfileCertificationsResponse struct {
	Certifications []*WorkProfileCertification `json:"certifications"`
	Total          int64                       `json:"total"`
}

// WorkProfileSkillGrantResponse содержит данные API-ответа.
type WorkProfileSkillGrantResponse struct {
	SkillGrant *WorkProfileSkillGrant `json:"skill_grant"`
}

// ListEffectiveWorkProfileSkillsResponse содержит данные API-ответа.
type ListEffectiveWorkProfileSkillsResponse struct {
	SkillGrants []*WorkProfileSkillGrant `json:"skill_grants"`
}

// BatchListEffectiveWorkProfileSkillsResponse содержит данные API-ответа.
type BatchListEffectiveWorkProfileSkillsResponse struct {
	Items []*EffectiveWorkProfileSkills `json:"items"`
}

// CheckWorkProfileHasSkillsResponse содержит данные API-ответа.
type CheckWorkProfileHasSkillsResponse struct {
	Allowed         bool     `json:"allowed"`
	MissingSkillIDs []string `json:"missing_skill_ids"`
}
