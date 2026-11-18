package models

import (
	"time"

	"github.com/google/uuid"
)

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

// UserProfileSortBy задаёт поле сортировки.
type UserProfileSortBy string

const (
	UserProfileSortByCreatedAt UserProfileSortBy = "created_at"
	UserProfileSortByUpdatedAt UserProfileSortBy = "updated_at"
	UserProfileSortByFullName  UserProfileSortBy = "full_name"
)

// WorkProfileSortBy задаёт поле сортировки.
type WorkProfileSortBy string

const (
	WorkProfileSortByCreatedAt      WorkProfileSortBy = "created_at"
	WorkProfileSortByUpdatedAt      WorkProfileSortBy = "updated_at"
	WorkProfileSortByFullName       WorkProfileSortBy = "full_name"
	WorkProfileSortByPosition       WorkProfileSortBy = "position"
	WorkProfileSortByStatus         WorkProfileSortBy = "status"
	WorkProfileSortByEmployeeNumber WorkProfileSortBy = "employee_number"
)

// SortOrder задаёт направление сортировки результатов.
type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
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

// OutboxEventStatus задаёт допустимое состояние модели.
type OutboxEventStatus string

const (
	OutboxEventStatusPending    OutboxEventStatus = "PENDING"
	OutboxEventStatusProcessing OutboxEventStatus = "PROCESSING"
	OutboxEventStatusSent       OutboxEventStatus = "SENT"
	OutboxEventStatusFailed     OutboxEventStatus = "FAILED"
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

// UserProfile описывает пользовательский профиль сотрудника.
type UserProfile struct {
	ID                     uuid.UUID              `json:"id"`
	UserID                 uuid.UUID              `json:"user_id"`
	FullName               string                 `json:"full_name"`
	Phone                  *string                `json:"phone,omitempty"`
	AvatarFileID           *uuid.UUID             `json:"avatar_file_id,omitempty"`
	PreferredContactMethod PreferredContactMethod `json:"preferred_contact_method"`
	CreatedAt              time.Time              `json:"created_at"`
	UpdatedAt              time.Time              `json:"updated_at"`
}

// WorkProfile описывает рабочий профиль сотрудника.
type WorkProfile struct {
	ID             uuid.UUID         `json:"id"`
	UserProfileID  uuid.UUID         `json:"user_profile_id"`
	DepartmentID   uuid.UUID         `json:"department_id"`
	EmployeeNumber *string           `json:"employee_number,omitempty"`
	Position       string            `json:"position"`
	Status         WorkProfileStatus `json:"status"`
	DeactivatedAt  *time.Time        `json:"deactivated_at,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// WorkProfileDetails объединяет рабочий профиль и связанные с ним данные.
type WorkProfileDetails struct {
	WorkProfile *WorkProfile `json:"work_profile"`
	UserProfile *UserProfile `json:"user_profile"`
}

// WorkProfileStatusHistory описывает доменную модель.
type WorkProfileStatusHistory struct {
	ID              uuid.UUID          `json:"id"`
	WorkProfileID   uuid.UUID          `json:"work_profile_id"`
	FromStatus      *WorkProfileStatus `json:"from_status,omitempty"`
	ToStatus        WorkProfileStatus  `json:"to_status"`
	Reason          string             `json:"reason"`
	ChangedByUserID *uuid.UUID         `json:"changed_by_user_id,omitempty"`
	RequestID       *string            `json:"request_id,omitempty"`
	CreatedAt       time.Time          `json:"created_at"`
}

// OutboxEvent описывает событие outbox.
type OutboxEvent struct {
	ID            uuid.UUID         `json:"id"`
	AggregateType string            `json:"aggregate_type"`
	AggregateID   uuid.UUID         `json:"aggregate_id"`
	EventType     string            `json:"event_type"`
	Payload       []byte            `json:"payload"`
	Status        OutboxEventStatus `json:"status"`
	Attempts      int               `json:"attempts"`
	LastError     *string           `json:"last_error,omitempty"`
	NextAttemptAt time.Time         `json:"next_attempt_at"`
	LockedAt      *time.Time        `json:"locked_at,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	SentAt        *time.Time        `json:"sent_at,omitempty"`
}

// CertificationType задаёт тип доменной модели.
type CertificationType struct {
	ID                  uuid.UUID `json:"id"`
	Code                string    `json:"code"`
	Name                string    `json:"name"`
	Description         *string   `json:"description,omitempty"`
	DefaultValidityDays *int32    `json:"default_validity_days,omitempty"`
	RequiresFile        bool      `json:"requires_file"`
	Active              bool      `json:"active"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// CertificationTypeSkill описывает доменную модель.
type CertificationTypeSkill struct {
	ID                  uuid.UUID `json:"id"`
	CertificationTypeID uuid.UUID `json:"certification_type_id"`
	SkillID             uuid.UUID `json:"skill_id"`
	ProficiencyLevel    *string   `json:"proficiency_level,omitempty"`
	Active              bool      `json:"active"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// WorkProfileCertification описывает доменную модель.
type WorkProfileCertification struct {
	ID                  uuid.UUID           `json:"id"`
	WorkProfileID       uuid.UUID           `json:"work_profile_id"`
	CertificationTypeID uuid.UUID           `json:"certification_type_id"`
	CertificateNumber   *string             `json:"certificate_number,omitempty"`
	Issuer              *string             `json:"issuer,omitempty"`
	IssuedAt            *time.Time          `json:"issued_at,omitempty"`
	ExpiresAt           *time.Time          `json:"expires_at,omitempty"`
	Status              CertificationStatus `json:"status"`
	CertificateFileID   *uuid.UUID          `json:"certificate_file_id,omitempty"`
	VerifiedByUserID    *uuid.UUID          `json:"verified_by_user_id,omitempty"`
	VerifiedAt          *time.Time          `json:"verified_at,omitempty"`
	RejectionReason     *string             `json:"rejection_reason,omitempty"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

// WorkProfileSkillGrant описывает доменную модель.
type WorkProfileSkillGrant struct {
	ID               uuid.UUID            `json:"id"`
	WorkProfileID    uuid.UUID            `json:"work_profile_id"`
	SkillID          uuid.UUID            `json:"skill_id"`
	SourceType       SkillGrantSourceType `json:"source_type"`
	SourceID         *uuid.UUID           `json:"source_id,omitempty"`
	ProficiencyLevel *string              `json:"proficiency_level,omitempty"`
	ValidUntil       *time.Time           `json:"valid_until,omitempty"`
	Active           bool                 `json:"active"`
	CreatedAt        time.Time            `json:"created_at"`
	RevokedAt        *time.Time           `json:"revoked_at,omitempty"`
}

// CreateUserProfileInput задаёт входные данные операции.
type CreateUserProfileInput struct {
	UserID                 uuid.UUID
	FullName               string
	Phone                  *string
	AvatarFileID           *uuid.UUID
	PreferredContactMethod PreferredContactMethod
	ActorUserID            *uuid.UUID
	ActorRoles             []string
}

// CreateUserProfileResult содержит результат операции.
type CreateUserProfileResult struct {
	UserProfile *UserProfile
}

// GetUserProfileByIDInput задаёт входные данные операции.
type GetUserProfileByIDInput struct {
	ID          uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// GetUserProfileByIDResult содержит результат операции.
type GetUserProfileByIDResult struct {
	UserProfile *UserProfile
}

// GetUserProfileByUserIDInput задаёт входные данные операции.
type GetUserProfileByUserIDInput struct {
	UserID      uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// GetUserProfileByUserIDResult содержит результат операции.
type GetUserProfileByUserIDResult struct {
	UserProfile *UserProfile
}

// GetMyUserProfileInput задаёт входные данные операции.
type GetMyUserProfileInput struct {
	ActorUserID *uuid.UUID
}

// GetMyUserProfileResult содержит результат операции.
type GetMyUserProfileResult struct {
	UserProfile *UserProfile
}

// ListUserProfilesInput задаёт входные данные операции.
type ListUserProfilesInput struct {
	Query       *string
	SortBy      UserProfileSortBy
	SortOrder   SortOrder
	Limit       int32
	Offset      int32
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// ListUserProfilesResult содержит результат операции.
type ListUserProfilesResult struct {
	UserProfiles []*UserProfile
	Total        int64
}

// UpdateUserProfileInput задаёт входные данные операции.
type UpdateUserProfileInput struct {
	ID                     uuid.UUID
	FullName               *string
	Phone                  *string
	ClearPhone             bool
	AvatarFileID           *uuid.UUID
	ClearAvatarFileID      bool
	PreferredContactMethod *PreferredContactMethod
	ActorUserID            *uuid.UUID
	ActorRoles             []string
}

// UpdateUserProfileResult содержит результат операции.
type UpdateUserProfileResult struct {
	UserProfile *UserProfile
}

// CreateWorkProfileInput задаёт входные данные операции.
type CreateWorkProfileInput struct {
	UserProfileID  uuid.UUID
	DepartmentID   uuid.UUID
	EmployeeNumber *string
	Position       string
	ActorUserID    *uuid.UUID
	ActorRoles     []string
}

// CreateWorkProfileResult содержит результат операции.
type CreateWorkProfileResult struct {
	Details *WorkProfileDetails
}

// GetWorkProfileByIDInput задаёт входные данные операции.
type GetWorkProfileByIDInput struct {
	ID          uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// GetWorkProfileByIDResult содержит результат операции.
type GetWorkProfileByIDResult struct {
	Details *WorkProfileDetails
}

// GetWorkProfileByUserIDInput задаёт входные данные операции.
type GetWorkProfileByUserIDInput struct {
	UserID      uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// GetWorkProfileByUserIDResult содержит результат операции.
type GetWorkProfileByUserIDResult struct {
	Details *WorkProfileDetails
}

// ListWorkProfilesInput задаёт входные данные операции.
type ListWorkProfilesInput struct {
	DepartmentID *uuid.UUID
	Status       *WorkProfileStatus
	Query        *string
	SortBy       WorkProfileSortBy
	SortOrder    SortOrder
	Limit        int32
	Offset       int32
	ActorUserID  *uuid.UUID
	ActorRoles   []string
}

// ListWorkProfilesResult содержит результат операции.
type ListWorkProfilesResult struct {
	WorkProfiles []*WorkProfileDetails
	Total        int64
}

// UpdateWorkProfileInput задаёт входные данные операции.
type UpdateWorkProfileInput struct {
	ID                  uuid.UUID
	EmployeeNumber      *string
	ClearEmployeeNumber bool
	Position            *string
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

// UpdateWorkProfileResult содержит результат операции.
type UpdateWorkProfileResult struct {
	Details *WorkProfileDetails
}

// DeactivateWorkProfileInput задаёт входные данные операции.
type DeactivateWorkProfileInput struct {
	ID          uuid.UUID
	Reason      string
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// DeactivateWorkProfileResult содержит результат операции.
type DeactivateWorkProfileResult struct {
	Details *WorkProfileDetails
}

// ChangeWorkProfileDepartmentInput задаёт входные данные операции.
type ChangeWorkProfileDepartmentInput struct {
	ID           uuid.UUID
	DepartmentID uuid.UUID
	Reason       string
	ActorUserID  *uuid.UUID
	ActorRoles   []string
}

// ChangeWorkProfileDepartmentResult содержит результат операции.
type ChangeWorkProfileDepartmentResult struct {
	Details *WorkProfileDetails
}

// SetWorkProfileStatusInput задаёт входные данные операции.
type SetWorkProfileStatusInput struct {
	ID          uuid.UUID
	Status      WorkProfileStatus
	Reason      string
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// SetWorkProfileStatusResult содержит результат операции.
type SetWorkProfileStatusResult struct {
	Details *WorkProfileDetails
}

// GetWorkProfileStatusHistoryInput задаёт входные данные операции.
type GetWorkProfileStatusHistoryInput struct {
	WorkProfileID uuid.UUID
	Limit         int32
	Offset        int32
	ActorUserID   *uuid.UUID
	ActorRoles    []string
}

// GetWorkProfileStatusHistoryResult содержит результат операции.
type GetWorkProfileStatusHistoryResult struct {
	History []*WorkProfileStatusHistory
	Total   int64
}

// ResolveWorkingDepartmentInput задаёт входные данные операции.
type ResolveWorkingDepartmentInput struct {
	UserID uuid.UUID
}

// ResolveWorkingDepartmentResult содержит результат операции.
type ResolveWorkingDepartmentResult struct {
	UserProfileID     uuid.UUID
	WorkProfileID     uuid.UUID
	UserID            uuid.UUID
	DepartmentID      uuid.UUID
	WorkProfileStatus WorkProfileStatus
	CanOperate        bool
}

// CheckProfileCanJoinBrigadeInput задаёт входные данные операции.
type CheckProfileCanJoinBrigadeInput struct {
	UserID              *uuid.UUID
	WorkProfileID       *uuid.UUID
	BrigadeDepartmentID uuid.UUID
}

// CheckProfileCanJoinBrigadeResult содержит результат операции.
type CheckProfileCanJoinBrigadeResult struct {
	UserProfileID uuid.UUID
	WorkProfileID uuid.UUID
	UserID        uuid.UUID
	DepartmentID  uuid.UUID
	Allowed       bool
	Reason        CanJoinBrigadeReason
}

// CreateCertificationTypeInput задаёт входные данные операции.
type CreateCertificationTypeInput struct {
	Code                string
	Name                string
	Description         *string
	DefaultValidityDays *int32
	RequiresFile        bool
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

// CreateCertificationTypeResult содержит результат операции.
type CreateCertificationTypeResult struct {
	CertificationType *CertificationType
}

// UpdateCertificationTypeInput задаёт входные данные операции.
type UpdateCertificationTypeInput struct {
	ID                  uuid.UUID
	Code                *string
	Name                *string
	Description         *string
	ClearDescription    bool
	DefaultValidityDays *int32
	ClearValidityDays   bool
	RequiresFile        *bool
	Active              *bool
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

// UpdateCertificationTypeResult содержит результат операции.
type UpdateCertificationTypeResult struct {
	CertificationType *CertificationType
}

// ListCertificationTypesInput задаёт входные данные операции.
type ListCertificationTypesInput struct {
	Active      *bool
	Query       *string
	Limit       int32
	Offset      int32
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// ListCertificationTypesResult содержит результат операции.
type ListCertificationTypesResult struct {
	CertificationTypes []*CertificationType
	Total              int64
}

// AddCertificationTypeSkillInput задаёт входные данные операции.
type AddCertificationTypeSkillInput struct {
	CertificationTypeID uuid.UUID
	SkillID             uuid.UUID
	ProficiencyLevel    *string
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

// AddCertificationTypeSkillResult содержит результат операции.
type AddCertificationTypeSkillResult struct {
	CertificationTypeSkill *CertificationTypeSkill
}

// RemoveCertificationTypeSkillInput задаёт входные данные операции.
type RemoveCertificationTypeSkillInput struct {
	CertificationTypeID uuid.UUID
	SkillID             uuid.UUID
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

// ListCertificationTypeSkillsInput задаёт входные данные операции.
type ListCertificationTypeSkillsInput struct {
	CertificationTypeID uuid.UUID
	ActiveOnly          bool
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

// ListCertificationTypeSkillsResult содержит результат операции.
type ListCertificationTypeSkillsResult struct {
	Skills []*CertificationTypeSkill
}

// UploadWorkProfileCertificationInput задаёт входные данные операции.
type UploadWorkProfileCertificationInput struct {
	WorkProfileID       uuid.UUID
	CertificationTypeID uuid.UUID
	CertificateNumber   *string
	Issuer              *string
	IssuedAt            *time.Time
	ExpiresAt           *time.Time
	CertificateFileID   *uuid.UUID
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

// UploadWorkProfileCertificationResult содержит результат операции.
type UploadWorkProfileCertificationResult struct {
	Certification *WorkProfileCertification
}

// VerifyWorkProfileCertificationInput задаёт входные данные операции.
type VerifyWorkProfileCertificationInput struct {
	ID          uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// VerifyWorkProfileCertificationResult содержит результат операции.
type VerifyWorkProfileCertificationResult struct {
	Certification *WorkProfileCertification
	SkillGrants   []*WorkProfileSkillGrant
}

// RejectWorkProfileCertificationInput задаёт входные данные операции.
type RejectWorkProfileCertificationInput struct {
	ID              uuid.UUID
	RejectionReason string
	ActorUserID     *uuid.UUID
	ActorRoles      []string
}

// RejectWorkProfileCertificationResult содержит результат операции.
type RejectWorkProfileCertificationResult struct {
	Certification *WorkProfileCertification
}

// RevokeWorkProfileCertificationInput задаёт входные данные операции.
type RevokeWorkProfileCertificationInput struct {
	ID          uuid.UUID
	Reason      string
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// RevokeWorkProfileCertificationResult содержит результат операции.
type RevokeWorkProfileCertificationResult struct {
	Certification *WorkProfileCertification
	RevokedGrants []*WorkProfileSkillGrant
}

// ExpireWorkProfileCertificationsInput задаёт входные данные операции.
type ExpireWorkProfileCertificationsInput struct {
	Limit       int32
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// ExpireWorkProfileCertificationsResult содержит результат операции.
type ExpireWorkProfileCertificationsResult struct {
	ExpiredCertifications []*WorkProfileCertification
	RevokedGrants         []*WorkProfileSkillGrant
}

// ListWorkProfileCertificationsInput задаёт входные данные операции.
type ListWorkProfileCertificationsInput struct {
	WorkProfileID       uuid.UUID
	CertificationTypeID *uuid.UUID
	Status              *CertificationStatus
	Limit               int32
	Offset              int32
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

// ListWorkProfileCertificationsResult содержит результат операции.
type ListWorkProfileCertificationsResult struct {
	Certifications []*WorkProfileCertification
	Total          int64
}

// GrantManualWorkProfileSkillInput задаёт входные данные операции.
type GrantManualWorkProfileSkillInput struct {
	WorkProfileID    uuid.UUID
	SkillID          uuid.UUID
	ProficiencyLevel *string
	ValidUntil       *time.Time
	Reason           string
	ActorUserID      *uuid.UUID
	ActorRoles       []string
}

// GrantManualWorkProfileSkillResult содержит результат операции.
type GrantManualWorkProfileSkillResult struct {
	SkillGrant *WorkProfileSkillGrant
}

// RevokeWorkProfileSkillGrantInput задаёт входные данные операции.
type RevokeWorkProfileSkillGrantInput struct {
	ID          uuid.UUID
	Reason      string
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// RevokeWorkProfileSkillGrantResult содержит результат операции.
type RevokeWorkProfileSkillGrantResult struct {
	SkillGrant *WorkProfileSkillGrant
}

// ListEffectiveWorkProfileSkillsInput задаёт входные данные операции.
type ListEffectiveWorkProfileSkillsInput struct {
	WorkProfileID uuid.UUID
	ActorUserID   *uuid.UUID
	ActorRoles    []string
}

// ListEffectiveWorkProfileSkillsResult содержит результат операции.
type ListEffectiveWorkProfileSkillsResult struct {
	SkillGrants []*WorkProfileSkillGrant
}

// BatchListEffectiveWorkProfileSkillsInput задаёт входные данные операции.
type BatchListEffectiveWorkProfileSkillsInput struct {
	WorkProfileIDs []uuid.UUID
	ActorUserID    *uuid.UUID
	ActorRoles     []string
}

// BatchListEffectiveWorkProfileSkillsResult содержит результат операции.
type BatchListEffectiveWorkProfileSkillsResult struct {
	SkillGrantsByWorkProfileID map[uuid.UUID][]*WorkProfileSkillGrant
}

// CheckWorkProfileHasSkillsInput задаёт входные данные операции.
type CheckWorkProfileHasSkillsInput struct {
	WorkProfileID    uuid.UUID
	RequiredSkillIDs []uuid.UUID
	ActorUserID      *uuid.UUID
	ActorRoles       []string
}

// CheckWorkProfileHasSkillsResult содержит результат операции.
type CheckWorkProfileHasSkillsResult struct {
	Allowed         bool
	MissingSkillIDs []uuid.UUID
}
