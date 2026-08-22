package models

import (
	"time"

	"github.com/google/uuid"
)

type PreferredContactMethod string

const (
	PreferredContactMethodEmail PreferredContactMethod = "EMAIL"
	PreferredContactMethodPhone PreferredContactMethod = "PHONE"
	PreferredContactMethodPush  PreferredContactMethod = "PUSH"
)

type WorkProfileStatus string

const (
	WorkProfileStatusActive    WorkProfileStatus = "ACTIVE"
	WorkProfileStatusInactive  WorkProfileStatus = "INACTIVE"
	WorkProfileStatusOnShift   WorkProfileStatus = "ON_SHIFT"
	WorkProfileStatusOffShift  WorkProfileStatus = "OFF_SHIFT"
	WorkProfileStatusSuspended WorkProfileStatus = "SUSPENDED"
)

type UserProfileSortBy string

const (
	UserProfileSortByCreatedAt UserProfileSortBy = "created_at"
	UserProfileSortByUpdatedAt UserProfileSortBy = "updated_at"
	UserProfileSortByFullName  UserProfileSortBy = "full_name"
)

type WorkProfileSortBy string

const (
	WorkProfileSortByCreatedAt      WorkProfileSortBy = "created_at"
	WorkProfileSortByUpdatedAt      WorkProfileSortBy = "updated_at"
	WorkProfileSortByFullName       WorkProfileSortBy = "full_name"
	WorkProfileSortByPosition       WorkProfileSortBy = "position"
	WorkProfileSortByStatus         WorkProfileSortBy = "status"
	WorkProfileSortByEmployeeNumber WorkProfileSortBy = "employee_number"
)

type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
)

type CanJoinBrigadeReason string

const (
	CanJoinBrigadeReasonAllowed            CanJoinBrigadeReason = "ALLOWED"
	CanJoinBrigadeReasonNoWorkProfile      CanJoinBrigadeReason = "NO_WORK_PROFILE"
	CanJoinBrigadeReasonProfileInactive    CanJoinBrigadeReason = "PROFILE_INACTIVE"
	CanJoinBrigadeReasonProfileSuspended   CanJoinBrigadeReason = "PROFILE_SUSPENDED"
	CanJoinBrigadeReasonProfileOffShift    CanJoinBrigadeReason = "PROFILE_OFF_SHIFT"
	CanJoinBrigadeReasonDepartmentMismatch CanJoinBrigadeReason = "DEPARTMENT_MISMATCH"
)

type OutboxEventStatus string

const (
	OutboxEventStatusPending    OutboxEventStatus = "PENDING"
	OutboxEventStatusProcessing OutboxEventStatus = "PROCESSING"
	OutboxEventStatusSent       OutboxEventStatus = "SENT"
	OutboxEventStatusFailed     OutboxEventStatus = "FAILED"
)

type CertificationStatus string

const (
	CertificationStatusPending  CertificationStatus = "PENDING"
	CertificationStatusVerified CertificationStatus = "VERIFIED"
	CertificationStatusRejected CertificationStatus = "REJECTED"
	CertificationStatusExpired  CertificationStatus = "EXPIRED"
	CertificationStatusRevoked  CertificationStatus = "REVOKED"
)

type SkillGrantSourceType string

const (
	SkillGrantSourceTypeManual        SkillGrantSourceType = "MANUAL"
	SkillGrantSourceTypeCertification SkillGrantSourceType = "CERTIFICATION"
)

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

type WorkProfileDetails struct {
	WorkProfile *WorkProfile `json:"work_profile"`
	UserProfile *UserProfile `json:"user_profile"`
}

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

type CertificationTypeSkill struct {
	ID                  uuid.UUID `json:"id"`
	CertificationTypeID uuid.UUID `json:"certification_type_id"`
	SkillID             uuid.UUID `json:"skill_id"`
	ProficiencyLevel    *string   `json:"proficiency_level,omitempty"`
	Active              bool      `json:"active"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

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

type CreateUserProfileInput struct {
	UserID                 uuid.UUID
	FullName               string
	Phone                  *string
	AvatarFileID           *uuid.UUID
	PreferredContactMethod PreferredContactMethod
	ActorUserID            *uuid.UUID
	ActorRoles             []string
}

type CreateUserProfileResult struct {
	UserProfile *UserProfile
}

type GetUserProfileByIDInput struct {
	ID          uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

type GetUserProfileByIDResult struct {
	UserProfile *UserProfile
}

type GetUserProfileByUserIDInput struct {
	UserID      uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

type GetUserProfileByUserIDResult struct {
	UserProfile *UserProfile
}

type GetMyUserProfileInput struct {
	ActorUserID *uuid.UUID
}

type GetMyUserProfileResult struct {
	UserProfile *UserProfile
}

type ListUserProfilesInput struct {
	Query       *string
	SortBy      UserProfileSortBy
	SortOrder   SortOrder
	Limit       int32
	Offset      int32
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

type ListUserProfilesResult struct {
	UserProfiles []*UserProfile
	Total        int64
}

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

type UpdateUserProfileResult struct {
	UserProfile *UserProfile
}

type CreateWorkProfileInput struct {
	UserProfileID  uuid.UUID
	DepartmentID   uuid.UUID
	EmployeeNumber *string
	Position       string
	ActorUserID    *uuid.UUID
	ActorRoles     []string
}

type CreateWorkProfileResult struct {
	Details *WorkProfileDetails
}

type GetWorkProfileByIDInput struct {
	ID          uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

type GetWorkProfileByIDResult struct {
	Details *WorkProfileDetails
}

type GetWorkProfileByUserIDInput struct {
	UserID      uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

type GetWorkProfileByUserIDResult struct {
	Details *WorkProfileDetails
}

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

type ListWorkProfilesResult struct {
	WorkProfiles []*WorkProfileDetails
	Total        int64
}

type UpdateWorkProfileInput struct {
	ID                  uuid.UUID
	EmployeeNumber      *string
	ClearEmployeeNumber bool
	Position            *string
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

type UpdateWorkProfileResult struct {
	Details *WorkProfileDetails
}

type DeactivateWorkProfileInput struct {
	ID          uuid.UUID
	Reason      string
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

type DeactivateWorkProfileResult struct {
	Details *WorkProfileDetails
}

type ChangeWorkProfileDepartmentInput struct {
	ID           uuid.UUID
	DepartmentID uuid.UUID
	Reason       string
	ActorUserID  *uuid.UUID
	ActorRoles   []string
}

type ChangeWorkProfileDepartmentResult struct {
	Details *WorkProfileDetails
}

type SetWorkProfileStatusInput struct {
	ID          uuid.UUID
	Status      WorkProfileStatus
	Reason      string
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

type SetWorkProfileStatusResult struct {
	Details *WorkProfileDetails
}

type GetWorkProfileStatusHistoryInput struct {
	WorkProfileID uuid.UUID
	Limit         int32
	Offset        int32
	ActorUserID   *uuid.UUID
	ActorRoles    []string
}

type GetWorkProfileStatusHistoryResult struct {
	History []*WorkProfileStatusHistory
	Total   int64
}

type ResolveWorkingDepartmentInput struct {
	UserID uuid.UUID
}

type ResolveWorkingDepartmentResult struct {
	UserProfileID     uuid.UUID
	WorkProfileID     uuid.UUID
	UserID            uuid.UUID
	DepartmentID      uuid.UUID
	WorkProfileStatus WorkProfileStatus
	CanOperate        bool
}

type CheckProfileCanJoinBrigadeInput struct {
	UserID              *uuid.UUID
	WorkProfileID       *uuid.UUID
	BrigadeDepartmentID uuid.UUID
}

type CheckProfileCanJoinBrigadeResult struct {
	UserProfileID uuid.UUID
	WorkProfileID uuid.UUID
	UserID        uuid.UUID
	DepartmentID  uuid.UUID
	Allowed       bool
	Reason        CanJoinBrigadeReason
}

type CreateCertificationTypeInput struct {
	Code                string
	Name                string
	Description         *string
	DefaultValidityDays *int32
	RequiresFile        bool
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

type CreateCertificationTypeResult struct {
	CertificationType *CertificationType
}

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

type UpdateCertificationTypeResult struct {
	CertificationType *CertificationType
}

type ListCertificationTypesInput struct {
	Active      *bool
	Query       *string
	Limit       int32
	Offset      int32
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

type ListCertificationTypesResult struct {
	CertificationTypes []*CertificationType
	Total              int64
}

type AddCertificationTypeSkillInput struct {
	CertificationTypeID uuid.UUID
	SkillID             uuid.UUID
	ProficiencyLevel    *string
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

type AddCertificationTypeSkillResult struct {
	CertificationTypeSkill *CertificationTypeSkill
}

type RemoveCertificationTypeSkillInput struct {
	CertificationTypeID uuid.UUID
	SkillID             uuid.UUID
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

type ListCertificationTypeSkillsInput struct {
	CertificationTypeID uuid.UUID
	ActiveOnly          bool
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

type ListCertificationTypeSkillsResult struct {
	Skills []*CertificationTypeSkill
}

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

type UploadWorkProfileCertificationResult struct {
	Certification *WorkProfileCertification
}

type VerifyWorkProfileCertificationInput struct {
	ID          uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

type VerifyWorkProfileCertificationResult struct {
	Certification *WorkProfileCertification
	SkillGrants   []*WorkProfileSkillGrant
}

type RejectWorkProfileCertificationInput struct {
	ID              uuid.UUID
	RejectionReason string
	ActorUserID     *uuid.UUID
	ActorRoles      []string
}

type RejectWorkProfileCertificationResult struct {
	Certification *WorkProfileCertification
}

type RevokeWorkProfileCertificationInput struct {
	ID          uuid.UUID
	Reason      string
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

type RevokeWorkProfileCertificationResult struct {
	Certification *WorkProfileCertification
	RevokedGrants []*WorkProfileSkillGrant
}

type ExpireWorkProfileCertificationsInput struct {
	Limit       int32
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

type ExpireWorkProfileCertificationsResult struct {
	ExpiredCertifications []*WorkProfileCertification
	RevokedGrants         []*WorkProfileSkillGrant
}

type ListWorkProfileCertificationsInput struct {
	WorkProfileID       uuid.UUID
	CertificationTypeID *uuid.UUID
	Status              *CertificationStatus
	Limit               int32
	Offset              int32
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}

type ListWorkProfileCertificationsResult struct {
	Certifications []*WorkProfileCertification
	Total          int64
}

type GrantManualWorkProfileSkillInput struct {
	WorkProfileID    uuid.UUID
	SkillID          uuid.UUID
	ProficiencyLevel *string
	ValidUntil       *time.Time
	Reason           string
	ActorUserID      *uuid.UUID
	ActorRoles       []string
}

type GrantManualWorkProfileSkillResult struct {
	SkillGrant *WorkProfileSkillGrant
}

type RevokeWorkProfileSkillGrantInput struct {
	ID          uuid.UUID
	Reason      string
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

type RevokeWorkProfileSkillGrantResult struct {
	SkillGrant *WorkProfileSkillGrant
}

type ListEffectiveWorkProfileSkillsInput struct {
	WorkProfileID uuid.UUID
	ActorUserID   *uuid.UUID
	ActorRoles    []string
}

type ListEffectiveWorkProfileSkillsResult struct {
	SkillGrants []*WorkProfileSkillGrant
}

type BatchListEffectiveWorkProfileSkillsInput struct {
	WorkProfileIDs []uuid.UUID
	ActorUserID    *uuid.UUID
	ActorRoles     []string
}

type BatchListEffectiveWorkProfileSkillsResult struct {
	SkillGrantsByWorkProfileID map[uuid.UUID][]*WorkProfileSkillGrant
}

type CheckWorkProfileHasSkillsInput struct {
	WorkProfileID    uuid.UUID
	RequiredSkillIDs []uuid.UUID
	ActorUserID      *uuid.UUID
	ActorRoles       []string
}

type CheckWorkProfileHasSkillsResult struct {
	Allowed         bool
	MissingSkillIDs []uuid.UUID
}
