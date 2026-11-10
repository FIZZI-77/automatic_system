package models

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

// Brigade описывает бригаду, её принадлежность и рабочее состояние.
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

// BrigadeMember описывает участника бригады и его роль.
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

// Skill описывает профессиональный навык.
type Skill struct {
	ID            string `json:"id"`
	Code          string `json:"code"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Active        bool   `json:"active"`
	CreatedAtUnix int64  `json:"created_at"`
	UpdatedAtUnix int64  `json:"updated_at"`
}

// BrigadeSkill описывает доменную модель.
type BrigadeSkill struct {
	ID            string `json:"id"`
	BrigadeID     string `json:"brigade_id"`
	Skill         *Skill `json:"skill"`
	Active        bool   `json:"active"`
	CreatedAtUnix int64  `json:"created_at"`
	UpdatedAtUnix int64  `json:"updated_at"`
}

// BrigadeSchedule описывает доменную модель.
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

// BrigadeZone описывает доменную модель.
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

// BrigadeStatusHistory описывает доменную модель.
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

// BrigadeMemberHistory описывает доменную модель.
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

// BrigadeMemberStatusHistory описывает доменную модель.
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

// CreateBrigadeRequest содержит параметры API-запроса.
type CreateBrigadeRequest struct {
	DepartmentID   string  `json:"department_id" binding:"required,uuid"`
	Name           string  `json:"name" binding:"required,min=2,max=255"`
	Description    string  `json:"description" binding:"omitempty,max=1000"`
	Specialization *string `json:"specialization,omitempty" binding:"omitempty,max=100"`
}

// GetBrigadeByIDRequest содержит параметры API-запроса.
type GetBrigadeByIDRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

// ListBrigadesRequest содержит параметры API-запроса.
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

// UpdateBrigadeRequest содержит параметры API-запроса.
type UpdateBrigadeRequest struct {
	ID             string  `json:"id" binding:"required,uuid"`
	Name           *string `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	Description    *string `json:"description,omitempty" binding:"omitempty,max=1000"`
	Specialization *string `json:"specialization,omitempty" binding:"omitempty,max=100"`
}

// BrigadeReasonRequest содержит параметры API-запроса.
type BrigadeReasonRequest struct {
	ID              string `json:"id" binding:"required,uuid"`
	Reason          string `json:"reason" binding:"required"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty" binding:"omitempty,uuid"`
}

// SetBrigadeStatusRequest содержит параметры API-запроса.
type SetBrigadeStatusRequest struct {
	BrigadeID       string `json:"brigade_id" binding:"required,uuid"`
	Status          string `json:"status" binding:"required,oneof=active inactive available busy on_route on_site offline archived"`
	Reason          string `json:"reason" binding:"omitempty"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty" binding:"omitempty,uuid"`
}

// BrigadePageRequest содержит параметры API-запроса.
type BrigadePageRequest struct {
	BrigadeID string `json:"brigade_id" binding:"required,uuid"`
	Limit     *int32 `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset    *int32 `json:"offset,omitempty" binding:"omitempty,min=0"`
}

// AddBrigadeMemberRequest содержит параметры API-запроса.
type AddBrigadeMemberRequest struct {
	BrigadeID       string  `json:"brigade_id" binding:"required,uuid"`
	UserID          string  `json:"user_id" binding:"required,uuid"`
	ProfileID       *string `json:"profile_id,omitempty" binding:"omitempty,uuid"`
	Role            string  `json:"role" binding:"required,oneof=lead driver technician trainee"`
	ChangedByUserID string  `json:"changed_by_user_id,omitempty" binding:"omitempty,uuid"`
}

// BrigadeMemberMutationRequest содержит параметры API-запроса.
type BrigadeMemberMutationRequest struct {
	BrigadeID       string `json:"brigade_id" binding:"required,uuid"`
	MemberID        string `json:"member_id" binding:"required,uuid"`
	Reason          string `json:"reason,omitempty"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty" binding:"omitempty,uuid"`
}

// ChangeBrigadeMemberRoleRequest содержит параметры API-запроса.
type ChangeBrigadeMemberRoleRequest struct {
	BrigadeID       string `json:"brigade_id" binding:"required,uuid"`
	MemberID        string `json:"member_id" binding:"required,uuid"`
	Role            string `json:"role" binding:"required,oneof=lead driver technician trainee"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty" binding:"omitempty,uuid"`
}

// SetBrigadeMemberAvailabilityRequest содержит параметры API-запроса.
type SetBrigadeMemberAvailabilityRequest struct {
	BrigadeID       string `json:"brigade_id" binding:"required,uuid"`
	MemberID        string `json:"member_id" binding:"required,uuid"`
	Status          string `json:"status" binding:"required,oneof=available unavailable"`
	Reason          string `json:"reason,omitempty"`
	ChangedByUserID string `json:"changed_by_user_id,omitempty" binding:"omitempty,uuid"`
}

// ListBrigadeMembersRequest содержит параметры API-запроса.
type ListBrigadeMembersRequest struct {
	BrigadeID          string  `json:"brigade_id" binding:"required,uuid"`
	Active             *bool   `json:"active,omitempty"`
	Role               *string `json:"role,omitempty" binding:"omitempty,oneof=lead driver technician trainee"`
	AvailabilityStatus *string `json:"availability_status,omitempty" binding:"omitempty,oneof=available unavailable"`
	Limit              *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset             *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
}

// BrigadeMemberHistoryRequest содержит параметры API-запроса.
type BrigadeMemberHistoryRequest struct {
	BrigadeID string  `json:"brigade_id" binding:"required,uuid"`
	MemberID  *string `json:"member_id,omitempty" binding:"omitempty,uuid"`
	Limit     *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset    *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
}

// GetBrigadeByUserIDRequest содержит параметры API-запроса.
type GetBrigadeByUserIDRequest struct {
	UserID     string `json:"user_id" binding:"required,uuid"`
	OnlyActive *bool  `json:"only_active,omitempty"`
}

// CreateSkillRequest содержит параметры API-запроса.
type CreateSkillRequest struct {
	Code        string `json:"code" binding:"required,min=2,max=100"`
	Name        string `json:"name" binding:"required,min=2,max=255"`
	Description string `json:"description" binding:"omitempty,max=1000"`
}

// UpdateSkillRequest содержит параметры API-запроса.
type UpdateSkillRequest struct {
	ID          string  `json:"id" binding:"required,uuid"`
	Code        *string `json:"code,omitempty" binding:"omitempty,min=2,max=100"`
	Name        *string `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	Description *string `json:"description,omitempty" binding:"omitempty,max=1000"`
	Active      *bool   `json:"active,omitempty"`
}

// IDRequest содержит параметры API-запроса.
type IDRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

// ListSkillsRequest содержит параметры API-запроса.
type ListSkillsRequest struct {
	Active *bool   `json:"active,omitempty"`
	Query  *string `json:"query,omitempty"`
	Limit  *int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset *int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
}

// BrigadeSkillRequest содержит параметры API-запроса.
type BrigadeSkillRequest struct {
	BrigadeID string `json:"brigade_id" binding:"required,uuid"`
	SkillID   string `json:"skill_id" binding:"required,uuid"`
}

// ListBrigadeSkillsRequest содержит параметры API-запроса.
type ListBrigadeSkillsRequest struct {
	BrigadeID string `json:"brigade_id" binding:"required,uuid"`
	Active    *bool  `json:"active,omitempty"`
}

// SetBrigadeScheduleRequest содержит параметры API-запроса.
type SetBrigadeScheduleRequest struct {
	BrigadeID string                 `json:"brigade_id" binding:"required,uuid"`
	Items     []*BrigadeScheduleItem `json:"items" binding:"required,min=1"`
}

// BrigadeScheduleItem описывает доменную модель.
type BrigadeScheduleItem struct {
	DayOfWeek int32   `json:"day_of_week" binding:"required,min=1,max=7"`
	StartsAt  string  `json:"starts_at" binding:"required"`
	EndsAt    string  `json:"ends_at" binding:"required"`
	Timezone  string  `json:"timezone" binding:"required"`
	ValidFrom *string `json:"valid_from,omitempty"`
	ValidTo   *string `json:"valid_to,omitempty"`
}

// ListBrigadeScheduleRequest содержит параметры API-запроса.
type ListBrigadeScheduleRequest struct {
	BrigadeID string `json:"brigade_id" binding:"required,uuid"`
	Active    *bool  `json:"active,omitempty"`
}

// CreateBrigadeZoneRequest содержит параметры API-запроса.
type CreateBrigadeZoneRequest struct {
	BrigadeID    string `json:"brigade_id" binding:"required,uuid"`
	DepartmentID string `json:"department_id" binding:"required,uuid"`
	Name         string `json:"name" binding:"required,min=2,max=255"`
	GeoJSON      string `json:"geo_json" binding:"required"`
	Priority     int32  `json:"priority"`
}

// UpdateBrigadeZoneRequest содержит параметры API-запроса.
type UpdateBrigadeZoneRequest struct {
	ID       string  `json:"id" binding:"required,uuid"`
	Name     *string `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	GeoJSON  *string `json:"geo_json,omitempty"`
	Priority *int32  `json:"priority,omitempty"`
	Active   *bool   `json:"active,omitempty"`
}

// ListBrigadeZonesRequest содержит параметры API-запроса.
type ListBrigadeZonesRequest struct {
	BrigadeID string `json:"brigade_id" binding:"required,uuid"`
	Active    *bool  `json:"active,omitempty"`
}

// CheckBrigadeCoversPointRequest содержит параметры API-запроса.
type CheckBrigadeCoversPointRequest struct {
	BrigadeID string  `json:"brigade_id" binding:"required,uuid"`
	Longitude float64 `json:"longitude" binding:"required,longitude"`
	Latitude  float64 `json:"latitude" binding:"required,latitude"`
}

// FindBrigadesByPointRequest содержит параметры API-запроса.
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

// GetAvailableBrigadesRequest содержит параметры API-запроса.
type GetAvailableBrigadesRequest struct {
	DepartmentID     string   `json:"department_id" binding:"required,uuid"`
	Longitude        *float64 `json:"longitude,omitempty" binding:"omitempty,longitude"`
	Latitude         *float64 `json:"latitude,omitempty" binding:"omitempty,latitude"`
	RequiredSkillIDs []string `json:"required_skill_ids,omitempty" binding:"omitempty,dive,uuid"`
	RequiredRoles    []string `json:"required_roles,omitempty" binding:"omitempty,dive,oneof=lead driver technician trainee"`
	Limit            *int32   `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset           *int32   `json:"offset,omitempty" binding:"omitempty,min=0"`
}

// CheckBrigadeCanHandleTicketRequest содержит параметры API-запроса.
type CheckBrigadeCanHandleTicketRequest struct {
	BrigadeID        string   `json:"brigade_id" binding:"required,uuid"`
	DepartmentID     string   `json:"department_id" binding:"required,uuid"`
	Longitude        float64  `json:"longitude" binding:"required,longitude"`
	Latitude         float64  `json:"latitude" binding:"required,latitude"`
	RequiredSkillIDs []string `json:"required_skill_ids,omitempty" binding:"omitempty,dive,uuid"`
	RequiredRoles    []string `json:"required_roles,omitempty" binding:"omitempty,dive,oneof=lead driver technician trainee"`
}

// BrigadeResponse содержит данные API-ответа.
type BrigadeResponse struct {
	Brigade *Brigade `json:"brigade"`
}
// ListBrigadesResponse содержит данные API-ответа.
type ListBrigadesResponse struct {
	Brigades []*Brigade `json:"brigades"`
	Total    int64      `json:"total"`
}
// BrigadeMemberResponse содержит данные API-ответа.
type BrigadeMemberResponse struct {
	Member *BrigadeMember `json:"member"`
}
// ListBrigadeMembersResponse содержит данные API-ответа.
type ListBrigadeMembersResponse struct {
	Members []*BrigadeMember `json:"members"`
	Total   int64            `json:"total"`
}
// BrigadeStatusHistoryResponse содержит данные API-ответа.
type BrigadeStatusHistoryResponse struct {
	History []*BrigadeStatusHistory `json:"history"`
	Total   int64                   `json:"total"`
}
// BrigadeMemberHistoryResponse содержит данные API-ответа.
type BrigadeMemberHistoryResponse struct {
	History []*BrigadeMemberHistory `json:"history"`
	Total   int64                   `json:"total"`
}
// BrigadeMemberStatusHistoryResponse содержит данные API-ответа.
type BrigadeMemberStatusHistoryResponse struct {
	History []*BrigadeMemberStatusHistory `json:"history"`
	Total   int64                         `json:"total"`
}
// GetBrigadeByUserIDResponse содержит данные API-ответа.
type GetBrigadeByUserIDResponse struct {
	Brigade *Brigade       `json:"brigade"`
	Member  *BrigadeMember `json:"member"`
}
// SkillResponse содержит данные API-ответа.
type SkillResponse struct {
	Skill *Skill `json:"skill"`
}
// ListSkillsResponse содержит данные API-ответа.
type ListSkillsResponse struct {
	Skills []*Skill `json:"skills"`
	Total  int64    `json:"total"`
}
// BrigadeSkillResponse содержит данные API-ответа.
type BrigadeSkillResponse struct {
	BrigadeSkill *BrigadeSkill `json:"brigade_skill"`
}
// ListBrigadeSkillsResponse содержит данные API-ответа.
type ListBrigadeSkillsResponse struct {
	Skills []*BrigadeSkill `json:"skills"`
}
// BrigadeScheduleResponse содержит данные API-ответа.
type BrigadeScheduleResponse struct {
	Schedule []*BrigadeSchedule `json:"schedule"`
}
// BrigadeZoneResponse содержит данные API-ответа.
type BrigadeZoneResponse struct {
	Zone *BrigadeZone `json:"zone"`
}
// ListBrigadeZonesResponse содержит данные API-ответа.
type ListBrigadeZonesResponse struct {
	Zones []*BrigadeZone `json:"zones"`
}
// CheckBrigadeCoversPointResponse содержит данные API-ответа.
type CheckBrigadeCoversPointResponse struct {
	Covers       bool           `json:"covers"`
	MatchedZones []*BrigadeZone `json:"matched_zones"`
}
// CheckBrigadeCanHandleTicketResponse содержит данные API-ответа.
type CheckBrigadeCanHandleTicketResponse struct {
	CanHandle bool     `json:"can_handle"`
	Reasons   []string `json:"reasons"`
}
