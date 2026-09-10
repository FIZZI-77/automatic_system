package models

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

type Brigade struct {
	ID              string `json:"id"`
	DepartmentID    string `json:"department_id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	Status          string `json:"status"`
	Specialization  string `json:"specialization,omitempty"`
	CreatedAtUnix   int64  `json:"created_at"`
	UpdatedAtUnix   int64  `json:"updated_at"`
	DeactivatedUnix int64  `json:"deactivated_at,omitempty"`
	ArchivedAtUnix  int64  `json:"archived_at,omitempty"`
}

type BrigadeMember struct {
	ID                              string `json:"id"`
	BrigadeID                       string `json:"brigade_id"`
	UserID                          string `json:"user_id"`
	ProfileID                       string `json:"profile_id,omitempty"`
	Role                            string `json:"role"`
	Active                          bool   `json:"active"`
	AvailabilityStatus              string `json:"availability_status"`
	AvailabilityStatusChangedAtUnix int64  `json:"availability_status_changed_at"`
	JoinedAtUnix                    int64  `json:"joined_at"`
	LeftAtUnix                      int64  `json:"left_at,omitempty"`
	CreatedAtUnix                   int64  `json:"created_at"`
	UpdatedAtUnix                   int64  `json:"updated_at"`
}

type Skill struct {
	ID            string `json:"id"`
	Code          string `json:"code"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Active        bool   `json:"active"`
	CreatedAtUnix int64  `json:"created_at"`
	UpdatedAtUnix int64  `json:"updated_at"`
}

type BrigadeSkill struct {
	ID            string `json:"id"`
	BrigadeID     string `json:"brigade_id"`
	Skill         *Skill `json:"skill"`
	Active        bool   `json:"active"`
	CreatedAtUnix int64  `json:"created_at"`
	UpdatedAtUnix int64  `json:"updated_at"`
}

type BrigadeSchedule struct {
	ID            string `json:"id"`
	BrigadeID     string `json:"brigade_id"`
	DayOfWeek     int32  `json:"day_of_week"`
	StartsAt      string `json:"starts_at"`
	EndsAt        string `json:"ends_at"`
	Timezone      string `json:"timezone"`
	Active        bool   `json:"active"`
	ValidFrom     string `json:"valid_from,omitempty"`
	ValidTo       string `json:"valid_to,omitempty"`
	CreatedAtUnix int64  `json:"created_at"`
	UpdatedAtUnix int64  `json:"updated_at"`
}

type BrigadeZone struct {
	ID            string `json:"id"`
	BrigadeID     string `json:"brigade_id"`
	DepartmentID  string `json:"department_id"`
	Name          string `json:"name"`
	GeoJSON       string `json:"geo_json"`
	Priority      int32  `json:"priority"`
	Active        bool   `json:"active"`
	CreatedAtUnix int64  `json:"created_at"`
	UpdatedAtUnix int64  `json:"updated_at"`
}

type BrigadeStatusHistory struct {
	ID              string `json:"id"`
	BrigadeID       string `json:"brigade_id"`
	FromStatus      string `json:"from_status,omitempty"`
	ToStatus        string `json:"to_status"`
	Reason          string `json:"reason"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	CreatedAtUnix   int64  `json:"created_at"`
}

type BrigadeMemberHistory struct {
	ID              string `json:"id"`
	BrigadeID       string `json:"brigade_id"`
	MemberID        string `json:"member_id,omitempty"`
	UserID          string `json:"user_id"`
	ProfileID       string `json:"profile_id,omitempty"`
	Action          string `json:"action"`
	OldRole         string `json:"old_role,omitempty"`
	NewRole         string `json:"new_role,omitempty"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	CreatedAtUnix   int64  `json:"created_at"`
}

type BrigadeMemberStatusHistory struct {
	ID              string `json:"id"`
	BrigadeID       string `json:"brigade_id"`
	MemberID        string `json:"member_id,omitempty"`
	UserID          string `json:"user_id"`
	FromStatus      string `json:"from_status,omitempty"`
	ToStatus        string `json:"to_status"`
	Reason          string `json:"reason"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	CreatedAtUnix   int64  `json:"created_at"`
}

type CreateBrigadeRequest struct {
	DepartmentID   string  `json:"department_id" binding:"required,uuid"`
	Name           string  `json:"name" binding:"required,min=2,max=255"`
	Description    string  `json:"description" binding:"omitempty,max=1000"`
	Specialization *string `json:"specialization,omitempty" binding:"omitempty,max=100"`
}

type GetBrigadeByIDRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

type ListBrigadesRequest struct {
	DepartmentID   *string `json:"department_id,omitempty" binding:"omitempty,uuid"`
	Status         *string `json:"status,omitempty" binding:"omitempty,oneof=active inactive available busy on_route on_site offline archived"`
	Specialization *string `json:"specialization,omitempty" binding:"omitempty,max=100"`
	CreatedFrom    *string `json:"created_from,omitempty" binding:"omitempty,datetime=2006-01-02T15:04:05Z"`
	CreatedTo      *string `json:"created_to,omitempty" binding:"omitempty,datetime=2006-01-02T15:04:05Z"`
	Limit          *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset         *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
	SortBy         *string `json:"sort_by,omitempty" binding:"omitempty,oneof=created_at updated_at name status"`
	SortOrder      *string `json:"sort_order,omitempty" binding:"omitempty,oneof=asc desc"`
}

type UpdateBrigadeRequest struct {
	ID             string  `json:"id" binding:"required,uuid"`
	Name           *string `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	Description    *string `json:"description,omitempty" binding:"omitempty,max=1000"`
	Specialization *string `json:"specialization,omitempty" binding:"omitempty,max=100"`
}

type BrigadeReasonRequest struct {
	ID              string `json:"id" binding:"required,uuid"`
	Reason          string `json:"reason" binding:"required"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty" binding:"omitempty,uuid"`
}

type SetBrigadeStatusRequest struct {
	BrigadeID       string `json:"brigade_id" binding:"required,uuid"`
	Status          string `json:"status" binding:"required,oneof=active inactive available busy on_route on_site offline archived"`
	Reason          string `json:"reason" binding:"omitempty"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty" binding:"omitempty,uuid"`
}

type BrigadePageRequest struct {
	BrigadeID string `json:"brigade_id" binding:"required,uuid"`
	Limit     *int32 `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset    *int32 `json:"offset,omitempty" binding:"omitempty,min=0"`
}

type AddBrigadeMemberRequest struct {
	BrigadeID       string  `json:"brigade_id" binding:"required,uuid"`
	UserID          string  `json:"user_id" binding:"required,uuid"`
	ProfileID       *string `json:"profile_id,omitempty" binding:"omitempty,uuid"`
	Role            string  `json:"role" binding:"required,oneof=lead driver technician trainee"`
	ChangedByUserID string  `json:"changed_by_user_id,omitempty" binding:"omitempty,uuid"`
}

type BrigadeMemberMutationRequest struct {
	BrigadeID       string `json:"brigade_id" binding:"required,uuid"`
	MemberID        string `json:"member_id" binding:"required,uuid"`
	Reason          string `json:"reason,omitempty"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty" binding:"omitempty,uuid"`
}

type ChangeBrigadeMemberRoleRequest struct {
	BrigadeID       string `json:"brigade_id" binding:"required,uuid"`
	MemberID        string `json:"member_id" binding:"required,uuid"`
	Role            string `json:"role" binding:"required,oneof=lead driver technician trainee"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty" binding:"omitempty,uuid"`
}

type SetBrigadeMemberAvailabilityRequest struct {
	BrigadeID       string `json:"brigade_id" binding:"required,uuid"`
	MemberID        string `json:"member_id" binding:"required,uuid"`
	Status          string `json:"status" binding:"required,oneof=available unavailable"`
	Reason          string `json:"reason,omitempty"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty" binding:"omitempty,uuid"`
}

type ListBrigadeMembersRequest struct {
	BrigadeID          string  `json:"brigade_id" binding:"required,uuid"`
	Active             *bool   `json:"active,omitempty"`
	Role               *string `json:"role,omitempty" binding:"omitempty,oneof=lead driver technician trainee"`
	AvailabilityStatus *string `json:"availability_status,omitempty" binding:"omitempty,oneof=available unavailable"`
	Limit              *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset             *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
}

type BrigadeMemberHistoryRequest struct {
	BrigadeID string  `json:"brigade_id" binding:"required,uuid"`
	MemberID  *string `json:"member_id,omitempty" binding:"omitempty,uuid"`
	Limit     *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset    *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
}

type GetBrigadeByUserIDRequest struct {
	UserID     string `json:"user_id" binding:"required,uuid"`
	OnlyActive *bool  `json:"only_active,omitempty"`
}

type CreateSkillRequest struct {
	Code        string `json:"code" binding:"required,min=2,max=100"`
	Name        string `json:"name" binding:"required,min=2,max=255"`
	Description string `json:"description" binding:"omitempty,max=1000"`
}

type UpdateSkillRequest struct {
	ID          string  `json:"id" binding:"required,uuid"`
	Code        *string `json:"code,omitempty" binding:"omitempty,min=2,max=100"`
	Name        *string `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	Description *string `json:"description,omitempty" binding:"omitempty,max=1000"`
	Active      *bool   `json:"active,omitempty"`
}

type IDRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

type ListSkillsRequest struct {
	Active *bool   `json:"active,omitempty"`
	Query  *string `json:"query,omitempty"`
	Limit  *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
}

type BrigadeSkillRequest struct {
	BrigadeID string `json:"brigade_id" binding:"required,uuid"`
	SkillID   string `json:"skill_id" binding:"required,uuid"`
}

type ListBrigadeSkillsRequest struct {
	BrigadeID string `json:"brigade_id" binding:"required,uuid"`
	Active    *bool  `json:"active,omitempty"`
}

type SetBrigadeScheduleRequest struct {
	BrigadeID string                 `json:"brigade_id" binding:"required,uuid"`
	Items     []*BrigadeScheduleItem `json:"items" binding:"required,min=1"`
}

type BrigadeScheduleItem struct {
	DayOfWeek int32   `json:"day_of_week" binding:"required,min=1,max=7"`
	StartsAt  string  `json:"starts_at" binding:"required"`
	EndsAt    string  `json:"ends_at" binding:"required"`
	Timezone  string  `json:"timezone" binding:"required"`
	ValidFrom *string `json:"valid_from,omitempty"`
	ValidTo   *string `json:"valid_to,omitempty"`
}

type ListBrigadeScheduleRequest struct {
	BrigadeID string `json:"brigade_id" binding:"required,uuid"`
	Active    *bool  `json:"active,omitempty"`
}

type CreateBrigadeZoneRequest struct {
	BrigadeID    string `json:"brigade_id" binding:"required,uuid"`
	DepartmentID string `json:"department_id" binding:"required,uuid"`
	Name         string `json:"name" binding:"required,min=2,max=255"`
	GeoJSON      string `json:"geo_json" binding:"required"`
	Priority     int32  `json:"priority"`
}

type UpdateBrigadeZoneRequest struct {
	ID       string  `json:"id" binding:"required,uuid"`
	Name     *string `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	GeoJSON  *string `json:"geo_json,omitempty"`
	Priority *int32  `json:"priority,omitempty"`
	Active   *bool   `json:"active,omitempty"`
}

type ListBrigadeZonesRequest struct {
	BrigadeID string `json:"brigade_id" binding:"required,uuid"`
	Active    *bool  `json:"active,omitempty"`
}

type CheckBrigadeCoversPointRequest struct {
	BrigadeID string  `json:"brigade_id" binding:"required,uuid"`
	Longitude float64 `json:"longitude" binding:"required,longitude"`
	Latitude  float64 `json:"latitude" binding:"required,latitude"`
}

type FindBrigadesByPointRequest struct {
	DepartmentID     string   `json:"department_id" binding:"required,uuid"`
	Longitude        float64  `json:"longitude" binding:"required,longitude"`
	Latitude         float64  `json:"latitude" binding:"required,latitude"`
	OnlyAvailable    *bool    `json:"only_available,omitempty"`
	RequiredSkillIDs []string `json:"required_skill_ids,omitempty" binding:"omitempty,dive,uuid"`
	RequiredRoles    []string `json:"required_roles,omitempty" binding:"omitempty,dive,oneof=lead driver technician trainee"`
	Limit            *int32   `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset           *int32   `json:"offset,omitempty" binding:"omitempty,min=0"`
}

type GetAvailableBrigadesRequest struct {
	DepartmentID     string   `json:"department_id" binding:"required,uuid"`
	Longitude        *float64 `json:"longitude,omitempty" binding:"omitempty,longitude"`
	Latitude         *float64 `json:"latitude,omitempty" binding:"omitempty,latitude"`
	RequiredSkillIDs []string `json:"required_skill_ids,omitempty" binding:"omitempty,dive,uuid"`
	RequiredRoles    []string `json:"required_roles,omitempty" binding:"omitempty,dive,oneof=lead driver technician trainee"`
	Limit            *int32   `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset           *int32   `json:"offset,omitempty" binding:"omitempty,min=0"`
}

type CheckBrigadeCanHandleTicketRequest struct {
	BrigadeID        string   `json:"brigade_id" binding:"required,uuid"`
	DepartmentID     string   `json:"department_id" binding:"required,uuid"`
	Longitude        float64  `json:"longitude" binding:"required,longitude"`
	Latitude         float64  `json:"latitude" binding:"required,latitude"`
	RequiredSkillIDs []string `json:"required_skill_ids,omitempty" binding:"omitempty,dive,uuid"`
	RequiredRoles    []string `json:"required_roles,omitempty" binding:"omitempty,dive,oneof=lead driver technician trainee"`
}

type BrigadeResponse struct {
	Brigade *Brigade `json:"brigade"`
}
type ListBrigadesResponse struct {
	Brigades []*Brigade `json:"brigades"`
	Total    int64      `json:"total"`
}
type BrigadeMemberResponse struct {
	Member *BrigadeMember `json:"member"`
}
type ListBrigadeMembersResponse struct {
	Members []*BrigadeMember `json:"members"`
	Total   int64            `json:"total"`
}
type BrigadeStatusHistoryResponse struct {
	History []*BrigadeStatusHistory `json:"history"`
	Total   int64                   `json:"total"`
}
type BrigadeMemberHistoryResponse struct {
	History []*BrigadeMemberHistory `json:"history"`
	Total   int64                   `json:"total"`
}
type BrigadeMemberStatusHistoryResponse struct {
	History []*BrigadeMemberStatusHistory `json:"history"`
	Total   int64                         `json:"total"`
}
type GetBrigadeByUserIDResponse struct {
	Brigade *Brigade       `json:"brigade"`
	Member  *BrigadeMember `json:"member"`
}
type SkillResponse struct {
	Skill *Skill `json:"skill"`
}
type ListSkillsResponse struct {
	Skills []*Skill `json:"skills"`
	Total  int64    `json:"total"`
}
type BrigadeSkillResponse struct {
	BrigadeSkill *BrigadeSkill `json:"brigade_skill"`
}
type ListBrigadeSkillsResponse struct {
	Skills []*BrigadeSkill `json:"skills"`
}
type BrigadeScheduleResponse struct {
	Schedule []*BrigadeSchedule `json:"schedule"`
}
type BrigadeZoneResponse struct {
	Zone *BrigadeZone `json:"zone"`
}
type ListBrigadeZonesResponse struct {
	Zones []*BrigadeZone `json:"zones"`
}
type CheckBrigadeCoversPointResponse struct {
	Covers       bool           `json:"covers"`
	MatchedZones []*BrigadeZone `json:"matched_zones"`
}
type CheckBrigadeCanHandleTicketResponse struct {
	CanHandle bool     `json:"can_handle"`
	Reasons   []string `json:"reasons"`
}
