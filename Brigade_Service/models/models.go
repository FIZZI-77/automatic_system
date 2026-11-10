package models

import (
	"time"

	"github.com/google/uuid"
)

// BrigadeStatus задаёт допустимое состояние модели.
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

// BrigadeMemberRole описывает доменную модель.
type BrigadeMemberRole string

const (
	BrigadeMemberRoleLead       BrigadeMemberRole = "LEAD"
	BrigadeMemberRoleDriver     BrigadeMemberRole = "DRIVER"
	BrigadeMemberRoleTechnician BrigadeMemberRole = "TECHNICIAN"
	BrigadeMemberRoleTrainee    BrigadeMemberRole = "TRAINEE"
)

// BrigadeMemberAvailabilityStatus задаёт допустимое состояние модели.
type BrigadeMemberAvailabilityStatus string

const (
	BrigadeMemberAvailabilityAvailable   BrigadeMemberAvailabilityStatus = "AVAILABLE"
	BrigadeMemberAvailabilityUnavailable BrigadeMemberAvailabilityStatus = "UNAVAILABLE"
)

// BrigadeMemberHistoryAction описывает доменную модель.
type BrigadeMemberHistoryAction string

const (
	BrigadeMemberHistoryActionAdded       BrigadeMemberHistoryAction = "ADDED"
	BrigadeMemberHistoryActionRemoved     BrigadeMemberHistoryAction = "REMOVED"
	BrigadeMemberHistoryActionRoleChanged BrigadeMemberHistoryAction = "ROLE_CHANGED"
)

// BrigadeSortBy задаёт поле сортировки.
type BrigadeSortBy string

const (
	BrigadeSortByCreatedAt BrigadeSortBy = "created_at"
	BrigadeSortByUpdatedAt BrigadeSortBy = "updated_at"
	BrigadeSortByName      BrigadeSortBy = "name"
	BrigadeSortByStatus    BrigadeSortBy = "status"
)

// SortOrder задаёт направление сортировки результатов.
type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
)

// OutboxEventStatus задаёт допустимое состояние модели.
type OutboxEventStatus string

const (
	OutboxEventStatusPending    OutboxEventStatus = "PENDING"
	OutboxEventStatusProcessing OutboxEventStatus = "PROCESSING"
	OutboxEventStatusSent       OutboxEventStatus = "SENT"
	OutboxEventStatusFailed     OutboxEventStatus = "FAILED"
)

// Brigade описывает бригаду, её принадлежность и рабочее состояние.
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

// BrigadeMember описывает участника бригады и его роль.
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

// BrigadeMemberHistory описывает доменную модель.
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

// BrigadeMemberStatusHistory описывает доменную модель.
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

// Skill описывает профессиональный навык.
type Skill struct {
	ID          uuid.UUID `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// BrigadeSkill описывает доменную модель.
type BrigadeSkill struct {
	ID        uuid.UUID `json:"id"`
	BrigadeID uuid.UUID `json:"brigade_id"`
	SkillID   uuid.UUID `json:"skill_id"`
	Skill     *Skill    `json:"skill,omitempty"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BrigadeSchedule описывает доменную модель.
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

// BrigadeStatusHistory описывает доменную модель.
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

// BrigadeZone описывает доменную модель.
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

// OutboxEvent описывает событие outbox.
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

// CreateBrigadeInput задаёт входные данные операции.
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

// CreateBrigadeResult содержит результат операции.
type CreateBrigadeResult struct {
	Brigade *Brigade
}

// GetBrigadeByIDInput задаёт входные данные операции.
type GetBrigadeByIDInput struct {
	ID                uuid.UUID
	ActorUserID       *uuid.UUID // only for service
	ActorDepartmentID *uuid.UUID // only for service
	ActorRoles        []string   // only for service
}

// GetBrigadeByIDResult содержит результат операции.
type GetBrigadeByIDResult struct {
	Brigade *Brigade
}

// ListBrigadesInput задаёт входные данные операции.
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

// ListBrigadesResult содержит результат операции.
type ListBrigadesResult struct {
	Brigades []*Brigade
	Total    int64
}

// UpdateBrigadeInput задаёт входные данные операции.
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

// UpdateBrigadeResult содержит результат операции.
type UpdateBrigadeResult struct {
	Brigade *Brigade
}

// DeactivateBrigadeInput задаёт входные данные операции.
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

// DeactivateBrigadeResult содержит результат операции.
type DeactivateBrigadeResult struct {
	Brigade *Brigade
}

// ArchiveBrigadeInput задаёт входные данные операции.
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

// ArchiveBrigadeResult содержит результат операции.
type ArchiveBrigadeResult struct {
	Brigade *Brigade
}

// SetBrigadeStatusInput задаёт входные данные операции.
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

// SetBrigadeStatusResult содержит результат операции.
type SetBrigadeStatusResult struct {
	Brigade *Brigade
}

// GetBrigadeStatusHistoryInput задаёт входные данные операции.
type GetBrigadeStatusHistoryInput struct {
	BrigadeID         uuid.UUID
	Limit             int32
	Offset            int32
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// GetBrigadeStatusHistoryResult содержит результат операции.
type GetBrigadeStatusHistoryResult struct {
	History []*BrigadeStatusHistory
	Total   int64
}

// AddBrigadeMemberInput задаёт входные данные операции.
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
	InitialSkills     []BrigadeMemberSkillSeed
}

// BrigadeMemberSkillSeed описывает доменную модель.
type BrigadeMemberSkillSeed struct {
	WorkProfileID    uuid.UUID
	SkillID          uuid.UUID
	SourceGrantID    uuid.UUID
	ProficiencyLevel *string
	ValidUntil       *time.Time
	Active           bool
	OccurredAt       time.Time
}

// AddBrigadeMemberResult содержит результат операции.
type AddBrigadeMemberResult struct {
	Member *BrigadeMember
}

// RemoveBrigadeMemberInput задаёт входные данные операции.
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

// RemoveBrigadeMemberResult содержит результат операции.
type RemoveBrigadeMemberResult struct {
	Member *BrigadeMember
}

// ChangeBrigadeMemberRoleInput задаёт входные данные операции.
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

// ChangeBrigadeMemberRoleResult содержит результат операции.
type ChangeBrigadeMemberRoleResult struct {
	Member *BrigadeMember
}

// SetBrigadeMemberAvailabilityInput задаёт входные данные операции.
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

// SetBrigadeMemberAvailabilityResult содержит результат операции.
type SetBrigadeMemberAvailabilityResult struct {
	Member *BrigadeMember
}

// ListBrigadeMembersInput задаёт входные данные операции.
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

// ListBrigadeMembersResult содержит результат операции.
type ListBrigadeMembersResult struct {
	Members []*BrigadeMember
	Total   int64
}

// GetBrigadeMemberHistoryInput задаёт входные данные операции.
type GetBrigadeMemberHistoryInput struct {
	BrigadeID         uuid.UUID
	MemberID          *uuid.UUID
	Limit             int32
	Offset            int32
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// GetBrigadeMemberHistoryResult содержит результат операции.
type GetBrigadeMemberHistoryResult struct {
	History []*BrigadeMemberHistory
	Total   int64
}

// GetBrigadeMemberStatusHistoryInput задаёт входные данные операции.
type GetBrigadeMemberStatusHistoryInput struct {
	BrigadeID         uuid.UUID
	MemberID          *uuid.UUID
	Limit             int32
	Offset            int32
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// GetBrigadeMemberStatusHistoryResult содержит результат операции.
type GetBrigadeMemberStatusHistoryResult struct {
	History []*BrigadeMemberStatusHistory
	Total   int64
}

// GetBrigadeByUserIDInput задаёт входные данные операции.
type GetBrigadeByUserIDInput struct {
	UserID     uuid.UUID
	OnlyActive bool
}

// GetBrigadeByUserIDResult содержит результат операции.
type GetBrigadeByUserIDResult struct {
	Brigade *Brigade
	Member  *BrigadeMember
}

// CreateSkillInput задаёт входные данные операции.
type CreateSkillInput struct {
	Code        string
	Name        string
	Description string
	ActorUserID *uuid.UUID
	ActorRoles  []string
	RequestID   *string
	TraceID     *string
}

// CreateSkillResult содержит результат операции.
type CreateSkillResult struct {
	Skill *Skill
}

// UpdateSkillInput задаёт входные данные операции.
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

// UpdateSkillResult содержит результат операции.
type UpdateSkillResult struct {
	Skill *Skill
}

// DeactivateSkillInput задаёт входные данные операции.
type DeactivateSkillInput struct {
	ID          uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
	RequestID   *string
	TraceID     *string
}

// DeactivateSkillResult содержит результат операции.
type DeactivateSkillResult struct {
	Skill *Skill
}

// ListSkillsInput задаёт входные данные операции.
type ListSkillsInput struct {
	Active      *bool
	Query       *string
	Limit       int32
	Offset      int32
	ActorUserID *uuid.UUID
	ActorRoles  []string
}

// ListSkillsResult содержит результат операции.
type ListSkillsResult struct {
	Skills []*Skill
	Total  int64
}

// AddBrigadeSkillInput задаёт входные данные операции.
type AddBrigadeSkillInput struct {
	BrigadeID         uuid.UUID
	SkillID           uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

// AddBrigadeSkillResult содержит результат операции.
type AddBrigadeSkillResult struct {
	BrigadeSkill *BrigadeSkill
}

// RemoveBrigadeSkillInput задаёт входные данные операции.
type RemoveBrigadeSkillInput struct {
	BrigadeID         uuid.UUID
	SkillID           uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

// RemoveBrigadeSkillResult содержит результат операции.
type RemoveBrigadeSkillResult struct {
	BrigadeSkill *BrigadeSkill
}

// ListBrigadeSkillsInput задаёт входные данные операции.
type ListBrigadeSkillsInput struct {
	BrigadeID         uuid.UUID
	Active            *bool
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// ListBrigadeSkillsResult содержит результат операции.
type ListBrigadeSkillsResult struct {
	Skills []*BrigadeSkill
}

// BrigadeScheduleItem описывает доменную модель.
type BrigadeScheduleItem struct {
	DayOfWeek int16
	StartsAt  string
	EndsAt    string
	Timezone  string
	ValidFrom *time.Time
	ValidTo   *time.Time
}

// SetBrigadeScheduleInput задаёт входные данные операции.
type SetBrigadeScheduleInput struct {
	BrigadeID         uuid.UUID
	Items             []*BrigadeScheduleItem
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

// SetBrigadeScheduleResult содержит результат операции.
type SetBrigadeScheduleResult struct {
	Schedule []*BrigadeSchedule
}

// ListBrigadeScheduleInput задаёт входные данные операции.
type ListBrigadeScheduleInput struct {
	BrigadeID         uuid.UUID
	Active            *bool
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// ListBrigadeScheduleResult содержит результат операции.
type ListBrigadeScheduleResult struct {
	Schedule []*BrigadeSchedule
}

// CreateBrigadeZoneInput задаёт входные данные операции.
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

// CreateBrigadeZoneResult содержит результат операции.
type CreateBrigadeZoneResult struct {
	Zone *BrigadeZone
}

// UpdateBrigadeZoneInput задаёт входные данные операции.
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

// UpdateBrigadeZoneResult содержит результат операции.
type UpdateBrigadeZoneResult struct {
	Zone *BrigadeZone
}

// DeleteBrigadeZoneInput задаёт входные данные операции.
type DeleteBrigadeZoneInput struct {
	ID                uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}

// DeleteBrigadeZoneResult содержит результат операции.
type DeleteBrigadeZoneResult struct {
	Zone *BrigadeZone
}

// ListBrigadeZonesInput задаёт входные данные операции.
type ListBrigadeZonesInput struct {
	BrigadeID         uuid.UUID
	Active            *bool
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}

// ListBrigadeZonesResult содержит результат операции.
type ListBrigadeZonesResult struct {
	Zones []*BrigadeZone
}

// CheckBrigadeCoversPointInput задаёт входные данные операции.
type CheckBrigadeCoversPointInput struct {
	BrigadeID uuid.UUID
	Longitude float64
	Latitude  float64
}

// CheckBrigadeCoversPointResult содержит результат операции.
type CheckBrigadeCoversPointResult struct {
	Covers       bool
	MatchedZones []*BrigadeZone
}

// FindBrigadesByPointInput задаёт входные данные операции.
type FindBrigadesByPointInput struct {
	DepartmentID     uuid.UUID
	Longitude        float64
	Latitude         float64
	OnlyAvailable    bool
	RequiredSkillIDs []uuid.UUID
	RequiredRoles    []BrigadeMemberRole
	Limit            int32
	Offset           int32
}

// FindBrigadesByPointResult содержит результат операции.
type FindBrigadesByPointResult struct {
	Brigades []*Brigade
	Total    int64
}

// GetAvailableBrigadesInput задаёт входные данные операции.
type GetAvailableBrigadesInput struct {
	DepartmentID     uuid.UUID
	Longitude        *float64
	Latitude         *float64
	RequiredSkillIDs []uuid.UUID
	RequiredRoles    []BrigadeMemberRole
	Limit            int32
	Offset           int32
}

// GetAvailableBrigadesResult содержит результат операции.
type GetAvailableBrigadesResult struct {
	Brigades []*Brigade
	Total    int64
}

// CheckBrigadeCanHandleTicketInput задаёт входные данные операции.
type CheckBrigadeCanHandleTicketInput struct {
	BrigadeID        uuid.UUID
	DepartmentID     uuid.UUID
	Longitude        float64
	Latitude         float64
	RequiredSkillIDs []uuid.UUID
	RequiredRoles    []BrigadeMemberRole
}

// CheckBrigadeCanHandleTicketResult содержит результат операции.
type CheckBrigadeCanHandleTicketResult struct {
	CanHandle bool
	Reasons   []string
}
