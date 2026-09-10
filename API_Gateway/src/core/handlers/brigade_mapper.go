package handlers

import (
	"strings"

	"gateway/models"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
)

func ToProtoBrigadeStatus(status string) brigadev1.BrigadeStatus {
	switch normalizeEnum(status) {
	case "ACTIVE":
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_ACTIVE
	case "INACTIVE":
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_INACTIVE
	case "AVAILABLE":
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_AVAILABLE
	case "BUSY":
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_BUSY
	case "ON_ROUTE":
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_ON_ROUTE
	case "ON_SITE":
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_ON_SITE
	case "OFFLINE":
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_OFFLINE
	case "ARCHIVED":
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_ARCHIVED
	default:
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_UNSPECIFIED
	}
}

func FromProtoBrigadeStatus(status brigadev1.BrigadeStatus) string {
	switch status {
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_ACTIVE:
		return string(models.BrigadeStatusActive)
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_INACTIVE:
		return string(models.BrigadeStatusInactive)
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_AVAILABLE:
		return string(models.BrigadeStatusAvailable)
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_BUSY:
		return string(models.BrigadeStatusBusy)
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_ON_ROUTE:
		return string(models.BrigadeStatusOnRoute)
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_ON_SITE:
		return string(models.BrigadeStatusOnSite)
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_OFFLINE:
		return string(models.BrigadeStatusOffline)
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_ARCHIVED:
		return string(models.BrigadeStatusArchived)
	default:
		return ""
	}
}

func ToProtoBrigadeMemberRole(role string) brigadev1.BrigadeMemberRole {
	switch normalizeEnum(role) {
	case "LEAD":
		return brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_LEAD
	case "DRIVER":
		return brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_DRIVER
	case "TECHNICIAN":
		return brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_TECHNICIAN
	case "TRAINEE":
		return brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_TRAINEE
	default:
		return brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_UNSPECIFIED
	}
}

func FromProtoBrigadeMemberRole(role brigadev1.BrigadeMemberRole) string {
	switch role {
	case brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_LEAD:
		return string(models.BrigadeMemberRoleLead)
	case brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_DRIVER:
		return string(models.BrigadeMemberRoleDriver)
	case brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_TECHNICIAN:
		return string(models.BrigadeMemberRoleTechnician)
	case brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_TRAINEE:
		return string(models.BrigadeMemberRoleTrainee)
	default:
		return ""
	}
}

func ToProtoBrigadeMemberRoles(roles []string) []brigadev1.BrigadeMemberRole {
	result := make([]brigadev1.BrigadeMemberRole, 0, len(roles))
	for _, role := range roles {
		result = append(result, ToProtoBrigadeMemberRole(role))
	}
	return result
}

func ToProtoBrigadeMemberAvailability(status string) brigadev1.BrigadeMemberAvailabilityStatus {
	switch normalizeEnum(status) {
	case "AVAILABLE":
		return brigadev1.BrigadeMemberAvailabilityStatus_BRIGADE_MEMBER_AVAILABILITY_STATUS_AVAILABLE
	case "UNAVAILABLE":
		return brigadev1.BrigadeMemberAvailabilityStatus_BRIGADE_MEMBER_AVAILABILITY_STATUS_UNAVAILABLE
	default:
		return brigadev1.BrigadeMemberAvailabilityStatus_BRIGADE_MEMBER_AVAILABILITY_STATUS_UNSPECIFIED
	}
}

func FromProtoBrigadeMemberAvailability(status brigadev1.BrigadeMemberAvailabilityStatus) string {
	switch status {
	case brigadev1.BrigadeMemberAvailabilityStatus_BRIGADE_MEMBER_AVAILABILITY_STATUS_AVAILABLE:
		return string(models.BrigadeMemberAvailabilityAvailable)
	case brigadev1.BrigadeMemberAvailabilityStatus_BRIGADE_MEMBER_AVAILABILITY_STATUS_UNAVAILABLE:
		return string(models.BrigadeMemberAvailabilityUnavailable)
	default:
		return ""
	}
}

func FromProtoBrigadeMemberHistoryAction(action brigadev1.BrigadeMemberHistoryAction) string {
	switch action {
	case brigadev1.BrigadeMemberHistoryAction_BRIGADE_MEMBER_HISTORY_ACTION_ADDED:
		return string(models.BrigadeMemberHistoryActionAdded)
	case brigadev1.BrigadeMemberHistoryAction_BRIGADE_MEMBER_HISTORY_ACTION_REMOVED:
		return string(models.BrigadeMemberHistoryActionRemoved)
	case brigadev1.BrigadeMemberHistoryAction_BRIGADE_MEMBER_HISTORY_ACTION_ROLE_CHANGED:
		return string(models.BrigadeMemberHistoryActionRoleChanged)
	default:
		return ""
	}
}

func ToProtoBrigadeSortBy(sortBy string) brigadev1.BrigadeSortBy {
	switch strings.ToLower(sortBy) {
	case string(models.BrigadeSortByCreatedAt):
		return brigadev1.BrigadeSortBy_BRIGADE_SORT_BY_CREATED_AT
	case string(models.BrigadeSortByUpdatedAt):
		return brigadev1.BrigadeSortBy_BRIGADE_SORT_BY_UPDATED_AT
	case string(models.BrigadeSortByName):
		return brigadev1.BrigadeSortBy_BRIGADE_SORT_BY_NAME
	case string(models.BrigadeSortByStatus):
		return brigadev1.BrigadeSortBy_BRIGADE_SORT_BY_STATUS
	default:
		return brigadev1.BrigadeSortBy_BRIGADE_SORT_BY_UNSPECIFIED
	}
}

func ToProtoBrigadeSortOrder(sortOrder string) brigadev1.SortOrder {
	switch strings.ToLower(sortOrder) {
	case string(models.SortOrderAsc):
		return brigadev1.SortOrder_SORT_ORDER_ASC
	case string(models.SortOrderDesc):
		return brigadev1.SortOrder_SORT_ORDER_DESC
	default:
		return brigadev1.SortOrder_SORT_ORDER_UNSPECIFIED
	}
}

func FromProtoBrigade(item *brigadev1.Brigade) *models.Brigade {
	if item == nil {
		return nil
	}
	return &models.Brigade{
		ID:              item.GetId(),
		DepartmentID:    item.GetDepartmentId(),
		Name:            item.GetName(),
		Description:     item.GetDescription(),
		Status:          FromProtoBrigadeStatus(item.GetStatus()),
		Specialization:  item.GetSpecialization(),
		CreatedAtUnix:   timestampUnix(item.GetCreatedAt()),
		UpdatedAtUnix:   timestampUnix(item.GetUpdatedAt()),
		DeactivatedUnix: timestampUnix(item.GetDeactivatedAt()),
		ArchivedAtUnix:  timestampUnix(item.GetArchivedAt()),
	}
}

func FromProtoBrigades(items []*brigadev1.Brigade) []*models.Brigade {
	result := make([]*models.Brigade, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoBrigade(item))
	}
	return result
}

func FromProtoBrigadeMember(item *brigadev1.BrigadeMember) *models.BrigadeMember {
	if item == nil {
		return nil
	}
	return &models.BrigadeMember{
		ID:                              item.GetId(),
		BrigadeID:                       item.GetBrigadeId(),
		UserID:                          item.GetUserId(),
		ProfileID:                       item.GetProfileId(),
		Role:                            FromProtoBrigadeMemberRole(item.GetRole()),
		Active:                          item.GetActive(),
		AvailabilityStatus:              FromProtoBrigadeMemberAvailability(item.GetAvailabilityStatus()),
		AvailabilityStatusChangedAtUnix: timestampUnix(item.GetAvailabilityStatusChangedAt()),
		JoinedAtUnix:                    timestampUnix(item.GetJoinedAt()),
		LeftAtUnix:                      timestampUnix(item.GetLeftAt()),
		CreatedAtUnix:                   timestampUnix(item.GetCreatedAt()),
		UpdatedAtUnix:                   timestampUnix(item.GetUpdatedAt()),
	}
}

func FromProtoBrigadeMembers(items []*brigadev1.BrigadeMember) []*models.BrigadeMember {
	result := make([]*models.BrigadeMember, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoBrigadeMember(item))
	}
	return result
}

func FromProtoSkill(item *brigadev1.Skill) *models.Skill {
	if item == nil {
		return nil
	}
	return &models.Skill{
		ID:            item.GetId(),
		Code:          item.GetCode(),
		Name:          item.GetName(),
		Description:   item.GetDescription(),
		Active:        item.GetActive(),
		CreatedAtUnix: timestampUnix(item.GetCreatedAt()),
		UpdatedAtUnix: timestampUnix(item.GetUpdatedAt()),
	}
}

func FromProtoSkills(items []*brigadev1.Skill) []*models.Skill {
	result := make([]*models.Skill, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoSkill(item))
	}
	return result
}

func FromProtoBrigadeSkill(item *brigadev1.BrigadeSkill) *models.BrigadeSkill {
	if item == nil {
		return nil
	}
	return &models.BrigadeSkill{
		ID:            item.GetId(),
		BrigadeID:     item.GetBrigadeId(),
		Skill:         FromProtoSkill(item.GetSkill()),
		Active:        item.GetActive(),
		CreatedAtUnix: timestampUnix(item.GetCreatedAt()),
		UpdatedAtUnix: timestampUnix(item.GetUpdatedAt()),
	}
}

func FromProtoBrigadeSkills(items []*brigadev1.BrigadeSkill) []*models.BrigadeSkill {
	result := make([]*models.BrigadeSkill, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoBrigadeSkill(item))
	}
	return result
}

func FromProtoBrigadeSchedule(item *brigadev1.BrigadeSchedule) *models.BrigadeSchedule {
	if item == nil {
		return nil
	}
	return &models.BrigadeSchedule{
		ID:            item.GetId(),
		BrigadeID:     item.GetBrigadeId(),
		DayOfWeek:     item.GetDayOfWeek(),
		StartsAt:      item.GetStartsAt(),
		EndsAt:        item.GetEndsAt(),
		Timezone:      item.GetTimezone(),
		Active:        item.GetActive(),
		ValidFrom:     item.GetValidFrom(),
		ValidTo:       item.GetValidTo(),
		CreatedAtUnix: timestampUnix(item.GetCreatedAt()),
		UpdatedAtUnix: timestampUnix(item.GetUpdatedAt()),
	}
}

func FromProtoBrigadeSchedules(items []*brigadev1.BrigadeSchedule) []*models.BrigadeSchedule {
	result := make([]*models.BrigadeSchedule, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoBrigadeSchedule(item))
	}
	return result
}

func FromProtoBrigadeZone(item *brigadev1.BrigadeZone) *models.BrigadeZone {
	if item == nil {
		return nil
	}
	return &models.BrigadeZone{
		ID:            item.GetId(),
		BrigadeID:     item.GetBrigadeId(),
		DepartmentID:  item.GetDepartmentId(),
		Name:          item.GetName(),
		GeoJSON:       item.GetGeoJson(),
		Priority:      item.GetPriority(),
		Active:        item.GetActive(),
		CreatedAtUnix: timestampUnix(item.GetCreatedAt()),
		UpdatedAtUnix: timestampUnix(item.GetUpdatedAt()),
	}
}

func FromProtoBrigadeZones(items []*brigadev1.BrigadeZone) []*models.BrigadeZone {
	result := make([]*models.BrigadeZone, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoBrigadeZone(item))
	}
	return result
}

func FromProtoBrigadeStatusHistory(item *brigadev1.BrigadeStatusHistory) *models.BrigadeStatusHistory {
	if item == nil {
		return nil
	}
	return &models.BrigadeStatusHistory{
		ID:              item.GetId(),
		BrigadeID:       item.GetBrigadeId(),
		FromStatus:      FromProtoBrigadeStatus(item.GetFromStatus()),
		ToStatus:        FromProtoBrigadeStatus(item.GetToStatus()),
		Reason:          item.GetReason(),
		ChangedByUserID: item.GetChangedByUserId(),
		RequestID:       item.GetRequestId(),
		CreatedAtUnix:   timestampUnix(item.GetCreatedAt()),
	}
}

func FromProtoBrigadeStatusHistoryItems(items []*brigadev1.BrigadeStatusHistory) []*models.BrigadeStatusHistory {
	result := make([]*models.BrigadeStatusHistory, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoBrigadeStatusHistory(item))
	}
	return result
}

func FromProtoBrigadeMemberHistory(item *brigadev1.BrigadeMemberHistory) *models.BrigadeMemberHistory {
	if item == nil {
		return nil
	}
	return &models.BrigadeMemberHistory{
		ID:              item.GetId(),
		BrigadeID:       item.GetBrigadeId(),
		MemberID:        item.GetMemberId(),
		UserID:          item.GetUserId(),
		ProfileID:       item.GetProfileId(),
		Action:          FromProtoBrigadeMemberHistoryAction(item.GetAction()),
		OldRole:         FromProtoBrigadeMemberRole(item.GetOldRole()),
		NewRole:         FromProtoBrigadeMemberRole(item.GetNewRole()),
		ChangedByUserID: item.GetChangedByUserId(),
		RequestID:       item.GetRequestId(),
		CreatedAtUnix:   timestampUnix(item.GetCreatedAt()),
	}
}

func FromProtoBrigadeMemberHistoryItems(items []*brigadev1.BrigadeMemberHistory) []*models.BrigadeMemberHistory {
	result := make([]*models.BrigadeMemberHistory, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoBrigadeMemberHistory(item))
	}
	return result
}

func FromProtoBrigadeMemberStatusHistory(item *brigadev1.BrigadeMemberStatusHistory) *models.BrigadeMemberStatusHistory {
	if item == nil {
		return nil
	}
	return &models.BrigadeMemberStatusHistory{
		ID:              item.GetId(),
		BrigadeID:       item.GetBrigadeId(),
		MemberID:        item.GetMemberId(),
		UserID:          item.GetUserId(),
		FromStatus:      FromProtoBrigadeMemberAvailability(item.GetFromStatus()),
		ToStatus:        FromProtoBrigadeMemberAvailability(item.GetToStatus()),
		Reason:          item.GetReason(),
		ChangedByUserID: item.GetChangedByUserId(),
		RequestID:       item.GetRequestId(),
		CreatedAtUnix:   timestampUnix(item.GetCreatedAt()),
	}
}

func FromProtoBrigadeMemberStatusHistoryItems(items []*brigadev1.BrigadeMemberStatusHistory) []*models.BrigadeMemberStatusHistory {
	result := make([]*models.BrigadeMemberStatusHistory, 0, len(items))
	for _, item := range items {
		result = append(result, FromProtoBrigadeMemberStatusHistory(item))
	}
	return result
}

func ToProtoScheduleItems(items []*models.BrigadeScheduleItem) []*brigadev1.BrigadeScheduleItem {
	result := make([]*brigadev1.BrigadeScheduleItem, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		result = append(result, &brigadev1.BrigadeScheduleItem{
			DayOfWeek: item.DayOfWeek,
			StartsAt:  item.StartsAt,
			EndsAt:    item.EndsAt,
			Timezone:  item.Timezone,
			ValidFrom: item.ValidFrom,
			ValidTo:   item.ValidTo,
		})
	}
	return result
}

func normalizeEnum(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}
