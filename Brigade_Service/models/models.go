package models

import (
	"time"

	"github.com/google/uuid"
)

type BrigadeStatus string

const (
	BrigadeStatusActive    BrigadeStatus = "ACTIVE"
	BrigadeStatusInactive  BrigadeStatus = "INACTIVE"
	BrigadeStatusAvailable BrigadeStatus = "AVAILABLE"
	BrigadeStatusBusy      BrigadeStatus = "BUSY"
	BrigadeStatusOnRoute   BrigadeStatus = "ON_ROUTE"
	BrigadeStatusOnSite    BrigadeStatus = "ON_SITE"
	BrigadeStatusOffline   BrigadeStatus = "OFFLINE"
	BrigadeStatusArchived  BrigadeStatus = "ARCHIVED"
)

type BrigadeMemberRole string

const (
	BrigadeMemberRoleLead       BrigadeMemberRole = "LEAD"
	BrigadeMemberRoleDriver     BrigadeMemberRole = "DRIVER"
	BrigadeMemberRoleTechnician BrigadeMemberRole = "TECHNICIAN"
	BrigadeMemberRoleTrainee    BrigadeMemberRole = "TRAINEE"
)

type BrigadeMemberAvailabilityStatus string

const (
	BrigadeMemberAvailabilityAvailable   BrigadeMemberAvailabilityStatus = "AVAILABLE"
	BrigadeMemberAvailabilityUnavailable BrigadeMemberAvailabilityStatus = "UNAVAILABLE"
)

type BrigadeMemberHistoryAction string

const (
	BrigadeMemberHistoryActionAdded       BrigadeMemberHistoryAction = "ADDED"
	BrigadeMemberHistoryActionRemoved     BrigadeMemberHistoryAction = "REMOVED"
	BrigadeMemberHistoryActionRoleChanged BrigadeMemberHistoryAction = "ROLE_CHANGED"
)

type BrigadeSortBy string

const (
	BrigadeSortByCreatedAt BrigadeSortBy = "created_at"
	BrigadeSortByUpdatedAt BrigadeSortBy = "updated_at"
	BrigadeSortByName      BrigadeSortBy = "name"
	BrigadeSortByStatus    BrigadeSortBy = "status"
)

type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
)

type OutboxEventStatus string

const (
	OutboxEventStatusPending    OutboxEventStatus = "PENDING"
	OutboxEventStatusProcessing OutboxEventStatus = "PROCESSING"
	OutboxEventStatusSent       OutboxEventStatus = "SENT"
	OutboxEventStatusFailed     OutboxEventStatus = "FAILED"
)

type Brigade struct {
	ID             uuid.UUID     `json:"id"`
	DepartmentID   uuid.UUID     `json:"department_id"`
	Name           string        `json:"name"`
	Description    string        `json:"description"`
	Status         BrigadeStatus `json:"status"`
	Specialization *string       `json:"specialization,omitempty"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
	DeactivatedAt  *time.Time    `json:"deactivated_at,omitempty"`
	ArchivedAt     *time.Time    `json:"archived_at,omitempty"`
}

type BrigadeMember struct {
	ID                          uuid.UUID                       `json:"id"`
	BrigadeID                   uuid.UUID                       `json:"brigade_id"`
	UserID                      uuid.UUID                       `json:"user_id"`
	ProfileID                   *uuid.UUID                      `json:"profile_id,omitempty"`
	Role                        BrigadeMemberRole               `json:"role"`
	Active                      bool                            `json:"active"`
	AvailabilityStatus          BrigadeMemberAvailabilityStatus `json:"availability_status"`
	AvailabilityStatusChangedAt time.Time                       `json:"availability_status_changed_at"`
	JoinedAt                    time.Time                       `json:"joined_at"`
	LeftAt                      *time.Time                      `json:"left_at,omitempty"`
	CreatedAt                   time.Time                       `json:"created_at"`
	UpdatedAt                   time.Time                       `json:"updated_at"`
}

type BrigadeMemberHistory struct {
	ID              uuid.UUID                  `json:"id"`
	BrigadeID       uuid.UUID                  `json:"brigade_id"`
	MemberID        *uuid.UUID                 `json:"member_id,omitempty"`
	UserID          uuid.UUID                  `json:"user_id"`
	ProfileID       *uuid.UUID                 `json:"profile_id,omitempty"`
	Action          BrigadeMemberHistoryAction `json:"action"`
	OldRole         *BrigadeMemberRole         `json:"old_role,omitempty"`
	NewRole         *BrigadeMemberRole         `json:"new_role,omitempty"`
	ChangedByUserID *uuid.UUID                 `json:"changed_by_user_id,omitempty"`
	RequestID       *string                    `json:"request_id,omitempty"`
	CreatedAt       time.Time                  `json:"created_at"`
}

type BrigadeMemberStatusHistory struct {
	ID              uuid.UUID                        `json:"id"`
	BrigadeID       uuid.UUID                        `json:"brigade_id"`
	MemberID        *uuid.UUID                       `json:"member_id,omitempty"`
	UserID          uuid.UUID                        `json:"user_id"`
	FromStatus      *BrigadeMemberAvailabilityStatus `json:"from_status,omitempty"`
	ToStatus        BrigadeMemberAvailabilityStatus  `json:"to_status"`
	Reason          string                           `json:"reason"`
	ChangedByUserID *uuid.UUID                       `json:"changed_by_user_id,omitempty"`
	RequestID       *string                          `json:"request_id,omitempty"`
	CreatedAt       time.Time                        `json:"created_at"`
}

type Skill struct {
	ID          uuid.UUID `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type BrigadeSkill struct {
	ID        uuid.UUID `json:"id"`
	BrigadeID uuid.UUID `json:"brigade_id"`
	SkillID   uuid.UUID `json:"skill_id"`
	Skill     *Skill    `json:"skill,omitempty"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type BrigadeSchedule struct {
	ID        uuid.UUID  `json:"id"`
	BrigadeID uuid.UUID  `json:"brigade_id"`
	DayOfWeek int16      `json:"day_of_week"`
	StartsAt  string     `json:"starts_at"`
	EndsAt    string     `json:"ends_at"`
	Timezone  string     `json:"timezone"`
	Active    bool       `json:"active"`
	ValidFrom *time.Time `json:"valid_from,omitempty"`
	ValidTo   *time.Time `json:"valid_to,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type BrigadeStatusHistory struct {
	ID              uuid.UUID      `json:"id"`
	BrigadeID       uuid.UUID      `json:"brigade_id"`
	FromStatus      *BrigadeStatus `json:"from_status,omitempty"`
	ToStatus        BrigadeStatus  `json:"to_status"`
	Reason          string         `json:"reason"`
	ChangedByUserID *uuid.UUID     `json:"changed_by_user_id,omitempty"`
	RequestID       *string        `json:"request_id,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
}

type BrigadeZone struct {
	ID           uuid.UUID `json:"id"`
	BrigadeID    uuid.UUID `json:"brigade_id"`
	DepartmentID uuid.UUID `json:"department_id"`
	Name         string    `json:"name"`
	GeoJSON      string    `json:"geo_json"`
	Priority     int32     `json:"priority"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type OutboxEvent struct {
	ID            uuid.UUID         `json:"id"`
	AggregateType string            `json:"aggregate_type"`
	AggregateID   uuid.UUID         `json:"aggregate_id"`
	EventType     string            `json:"event_type"`
	Payload       []byte            `json:"payload"`
	RequestID     *string           `json:"request_id,omitempty"`
	TraceID       *string           `json:"trace_id,omitempty"`
	Status        OutboxEventStatus `json:"status"`
	Attempts      int32             `json:"attempts"`
	LastError     *string           `json:"last_error,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	SentAt        *time.Time        `json:"sent_at,omitempty"`
}

type CreateBrigadeInput struct {
	DepartmentID      uuid.UUID
	Name              string
	Description       string
	Specialization    *string
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type CreateBrigadeResult struct {
	Brigade *Brigade
}

type GetBrigadeByIDInput struct {
	ID                uuid.UUID
	ActorUserID       *uuid.UUID // only for service
	ActorDepartmentID *uuid.UUID // only for service
	ActorRoles        []string   // only for service
}

type GetBrigadeByIDResult struct {
	Brigade *Brigade
}

type ListBrigadesInput struct {
	DepartmentID      *uuid.UUID
	Status            *BrigadeStatus
	Specialization    *string
	CreatedFrom       *time.Time
	CreatedTo         *time.Time
	SortBy            BrigadeSortBy
	SortOrder         SortOrder
	Limit             int32
	Offset            int32
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

type ListBrigadesResult struct {
	Brigades []*Brigade
	Total    int64
}

type UpdateBrigadeInput struct {
	ID                uuid.UUID
	Name              *string
	Description       *string
	Specialization    *string
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type UpdateBrigadeResult struct {
	Brigade *Brigade
}

type DeactivateBrigadeInput struct {
	ID                uuid.UUID
	Reason            string
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type DeactivateBrigadeResult struct {
	Brigade *Brigade
}

type ArchiveBrigadeInput struct {
	ID                uuid.UUID
	Reason            string
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type ArchiveBrigadeResult struct {
	Brigade *Brigade
}

type SetBrigadeStatusInput struct {
	BrigadeID         uuid.UUID
	Status            BrigadeStatus
	Reason            string
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type SetBrigadeStatusResult struct {
	Brigade *Brigade
}

type GetBrigadeStatusHistoryInput struct {
	BrigadeID         uuid.UUID
	Limit             int32
	Offset            int32
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

type GetBrigadeStatusHistoryResult struct {
	History []*BrigadeStatusHistory
	Total   int64
}

type AddBrigadeMemberInput struct {
	BrigadeID         uuid.UUID
	UserID            uuid.UUID
	ProfileID         *uuid.UUID
	Role              BrigadeMemberRole
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type AddBrigadeMemberResult struct {
	Member *BrigadeMember
}

type RemoveBrigadeMemberInput struct {
	BrigadeID         uuid.UUID
	MemberID          uuid.UUID
	Reason            string
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type RemoveBrigadeMemberResult struct {
	Member *BrigadeMember
}

type ChangeBrigadeMemberRoleInput struct {
	BrigadeID         uuid.UUID
	MemberID          uuid.UUID
	Role              BrigadeMemberRole
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type ChangeBrigadeMemberRoleResult struct {
	Member *BrigadeMember
}

type SetBrigadeMemberAvailabilityInput struct {
	BrigadeID         uuid.UUID
	MemberID          uuid.UUID
	Status            BrigadeMemberAvailabilityStatus
	Reason            string
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type SetBrigadeMemberAvailabilityResult struct {
	Member *BrigadeMember
}

type ListBrigadeMembersInput struct {
	BrigadeID          uuid.UUID
	Active             *bool
	Role               *BrigadeMemberRole
	AvailabilityStatus *BrigadeMemberAvailabilityStatus
	Limit              int32
	Offset             int32
	ActorUserID        *uuid.UUID
	ActorDepartmentID  *uuid.UUID
	ActorRoles         []string
}

type ListBrigadeMembersResult struct {
	Members []*BrigadeMember
	Total   int64
}

type GetBrigadeMemberHistoryInput struct {
	BrigadeID         uuid.UUID
	MemberID          *uuid.UUID
	Limit             int32
	Offset            int32
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

type GetBrigadeMemberHistoryResult struct {
	History []*BrigadeMemberHistory
	Total   int64
}

type GetBrigadeMemberStatusHistoryInput struct {
	BrigadeID         uuid.UUID
	MemberID          *uuid.UUID
	Limit             int32
	Offset            int32
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

type GetBrigadeMemberStatusHistoryResult struct {
	History []*BrigadeMemberStatusHistory
	Total   int64
}

type GetBrigadeByUserIDInput struct {
	UserID     uuid.UUID
	OnlyActive bool
}

type GetBrigadeByUserIDResult struct {
	Brigade *Brigade
	Member  *BrigadeMember
}

type CreateSkillInput struct {
	Code        string
	Name        string
	Description string
	ActorUserID *uuid.UUID
	ActorRoles  []string
	RequestID   *string
	TraceID     *string
}

type CreateSkillResult struct {
	Skill *Skill
}

type UpdateSkillInput struct {
	ID          uuid.UUID
	Code        *string
	Name        *string
	Description *string
	Active      *bool
	ActorUserID *uuid.UUID
	ActorRoles  []string
	RequestID   *string
	TraceID     *string
}

type UpdateSkillResult struct {
	Skill *Skill
}

type DeactivateSkillInput struct {
	ID          uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
	RequestID   *string
	TraceID     *string
}

type DeactivateSkillResult struct {
	Skill *Skill
}

type ListSkillsInput struct {
	Active      *bool
	Query       *string
	Limit       int32
	Offset      int32
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

type ListSkillsResult struct {
	Skills []*Skill
	Total  int64
}

type AddBrigadeSkillInput struct {
	BrigadeID         uuid.UUID
	SkillID           uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type AddBrigadeSkillResult struct {
	BrigadeSkill *BrigadeSkill
}

type RemoveBrigadeSkillInput struct {
	BrigadeID         uuid.UUID
	SkillID           uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type RemoveBrigadeSkillResult struct {
	BrigadeSkill *BrigadeSkill
}

type ListBrigadeSkillsInput struct {
	BrigadeID         uuid.UUID
	Active            *bool
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

type ListBrigadeSkillsResult struct {
	Skills []*BrigadeSkill
}

type BrigadeScheduleItem struct {
	DayOfWeek int16
	StartsAt  string
	EndsAt    string
	Timezone  string
	ValidFrom *time.Time
	ValidTo   *time.Time
}

type SetBrigadeScheduleInput struct {
	BrigadeID         uuid.UUID
	Items             []*BrigadeScheduleItem
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type SetBrigadeScheduleResult struct {
	Schedule []*BrigadeSchedule
}

type ListBrigadeScheduleInput struct {
	BrigadeID         uuid.UUID
	Active            *bool
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

type ListBrigadeScheduleResult struct {
	Schedule []*BrigadeSchedule
}

type CreateBrigadeZoneInput struct {
	BrigadeID         uuid.UUID
	DepartmentID      uuid.UUID
	Name              string
	GeoJSON           string
	Priority          int32
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type CreateBrigadeZoneResult struct {
	Zone *BrigadeZone
}

type UpdateBrigadeZoneInput struct {
	ID                uuid.UUID
	Name              *string
	GeoJSON           *string
	Priority          *int32
	Active            *bool
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type UpdateBrigadeZoneResult struct {
	Zone *BrigadeZone
}

type DeleteBrigadeZoneInput struct {
	ID                uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

type DeleteBrigadeZoneResult struct {
	Zone *BrigadeZone
}

type ListBrigadeZonesInput struct {
	BrigadeID         uuid.UUID
	Active            *bool
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

type ListBrigadeZonesResult struct {
	Zones []*BrigadeZone
}

type CheckBrigadeCoversPointInput struct {
	BrigadeID uuid.UUID
	Longitude float64
	Latitude  float64
}

type CheckBrigadeCoversPointResult struct {
	Covers       bool
	MatchedZones []*BrigadeZone
}

type FindBrigadesByPointInput struct {
	DepartmentID     uuid.UUID
	Longitude        float64
	Latitude         float64
	OnlyAvailable    bool
	RequiredSkillIDs []uuid.UUID
	Limit            int32
	Offset           int32
}

type FindBrigadesByPointResult struct {
	Brigades []*Brigade
	Total    int64
}

type GetAvailableBrigadesInput struct {
	DepartmentID     uuid.UUID
	Longitude        *float64
	Latitude         *float64
	RequiredSkillIDs []uuid.UUID
	Limit            int32
	Offset           int32
}

type GetAvailableBrigadesResult struct {
	Brigades []*Brigade
	Total    int64
}

type CheckBrigadeCanHandleTicketInput struct {
	BrigadeID        uuid.UUID
	DepartmentID     uuid.UUID
	Longitude        float64
	Latitude         float64
	RequiredSkillIDs []uuid.UUID
}

type CheckBrigadeCanHandleTicketResult struct {
	CanHandle bool
	Reasons   []string
}
