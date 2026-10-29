package handler

import (
	"time"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"brigade/models"
)

// ToProtoBrigadeStatus преобразует статус бригады в protobuf; неизвестный даёт UNSPECIFIED.
func ToProtoBrigadeStatus(status models.BrigadeStatus) brigadev1.BrigadeStatus {
	switch status {
	case models.BrigadeStatusActive:
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_ACTIVE
	case models.BrigadeStatusInactive:
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_INACTIVE
	case models.BrigadeStatusAvailable:
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_AVAILABLE
	case models.BrigadeStatusBusy:
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_BUSY
	case models.BrigadeStatusOnRoute:
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_ON_ROUTE
	case models.BrigadeStatusOnSite:
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_ON_SITE
	case models.BrigadeStatusOffline:
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_OFFLINE
	case models.BrigadeStatusArchived:
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_ARCHIVED
	default:
		return brigadev1.BrigadeStatus_BRIGADE_STATUS_UNSPECIFIED
	}
}

// FromProtoBrigadeStatus преобразует статус бригады в доменный;
// неизвестное значение возвращает как пустую строку.
func FromProtoBrigadeStatus(status brigadev1.BrigadeStatus) models.BrigadeStatus {
	switch status {
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_ACTIVE:
		return models.BrigadeStatusActive
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_INACTIVE:
		return models.BrigadeStatusInactive
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_AVAILABLE:
		return models.BrigadeStatusAvailable
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_BUSY:
		return models.BrigadeStatusBusy
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_ON_ROUTE:
		return models.BrigadeStatusOnRoute
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_ON_SITE:
		return models.BrigadeStatusOnSite
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_OFFLINE:
		return models.BrigadeStatusOffline
	case brigadev1.BrigadeStatus_BRIGADE_STATUS_ARCHIVED:
		return models.BrigadeStatusArchived
	default:
		return ""
	}
}

// ToProtoMemberRole преобразует роль участника в protobuf; неизвестная даёт UNSPECIFIED.
func ToProtoMemberRole(role models.BrigadeMemberRole) brigadev1.BrigadeMemberRole {
	switch role {
	case models.BrigadeMemberRoleLead:
		return brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_LEAD
	case models.BrigadeMemberRoleDriver:
		return brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_DRIVER
	case models.BrigadeMemberRoleTechnician:
		return brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_TECHNICIAN
	case models.BrigadeMemberRoleTrainee:
		return brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_TRAINEE
	default:
		return brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_UNSPECIFIED
	}
}

// FromProtoMemberRole преобразует роль участника в доменную;
// неизвестное значение возвращает как пустую строку.
func FromProtoMemberRole(role brigadev1.BrigadeMemberRole) models.BrigadeMemberRole {
	switch role {
	case brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_LEAD:
		return models.BrigadeMemberRoleLead
	case brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_DRIVER:
		return models.BrigadeMemberRoleDriver
	case brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_TECHNICIAN:
		return models.BrigadeMemberRoleTechnician
	case brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_TRAINEE:
		return models.BrigadeMemberRoleTrainee
	default:
		return ""
	}
}

// ToProtoMemberAvailabilityStatus преобразует доступность участника в protobuf;
// неизвестное значение даёт UNSPECIFIED.
func ToProtoMemberAvailabilityStatus(status models.BrigadeMemberAvailabilityStatus) brigadev1.BrigadeMemberAvailabilityStatus {
	switch status {
	case models.BrigadeMemberAvailabilityAvailable:
		return brigadev1.BrigadeMemberAvailabilityStatus_BRIGADE_MEMBER_AVAILABILITY_STATUS_AVAILABLE
	case models.BrigadeMemberAvailabilityUnavailable:
		return brigadev1.BrigadeMemberAvailabilityStatus_BRIGADE_MEMBER_AVAILABILITY_STATUS_UNAVAILABLE
	default:
		return brigadev1.BrigadeMemberAvailabilityStatus_BRIGADE_MEMBER_AVAILABILITY_STATUS_UNSPECIFIED
	}
}

// FromProtoMemberAvailabilityStatus преобразует доступность участника в доменную;
// неизвестное значение возвращает как пустую строку.
func FromProtoMemberAvailabilityStatus(status brigadev1.BrigadeMemberAvailabilityStatus) models.BrigadeMemberAvailabilityStatus {
	switch status {
	case brigadev1.BrigadeMemberAvailabilityStatus_BRIGADE_MEMBER_AVAILABILITY_STATUS_AVAILABLE:
		return models.BrigadeMemberAvailabilityAvailable
	case brigadev1.BrigadeMemberAvailabilityStatus_BRIGADE_MEMBER_AVAILABILITY_STATUS_UNAVAILABLE:
		return models.BrigadeMemberAvailabilityUnavailable
	default:
		return ""
	}
}

// ToProtoMemberHistoryAction преобразует добавление, исключение или смену роли
// в protobuf; неизвестное действие даёт UNSPECIFIED.
func ToProtoMemberHistoryAction(action models.BrigadeMemberHistoryAction) brigadev1.BrigadeMemberHistoryAction {
	switch action {
	case models.BrigadeMemberHistoryActionAdded:
		return brigadev1.BrigadeMemberHistoryAction_BRIGADE_MEMBER_HISTORY_ACTION_ADDED
	case models.BrigadeMemberHistoryActionRemoved:
		return brigadev1.BrigadeMemberHistoryAction_BRIGADE_MEMBER_HISTORY_ACTION_REMOVED
	case models.BrigadeMemberHistoryActionRoleChanged:
		return brigadev1.BrigadeMemberHistoryAction_BRIGADE_MEMBER_HISTORY_ACTION_ROLE_CHANGED
	default:
		return brigadev1.BrigadeMemberHistoryAction_BRIGADE_MEMBER_HISTORY_ACTION_UNSPECIFIED
	}
}

// FromProtoBrigadeSortBy преобразует поле сортировки бригад в доменное;
// неизвестное значение возвращает как пустую строку.
func FromProtoBrigadeSortBy(sortBy brigadev1.BrigadeSortBy) models.BrigadeSortBy {
	switch sortBy {
	case brigadev1.BrigadeSortBy_BRIGADE_SORT_BY_CREATED_AT:
		return models.BrigadeSortByCreatedAt
	case brigadev1.BrigadeSortBy_BRIGADE_SORT_BY_UPDATED_AT:
		return models.BrigadeSortByUpdatedAt
	case brigadev1.BrigadeSortBy_BRIGADE_SORT_BY_NAME:
		return models.BrigadeSortByName
	case brigadev1.BrigadeSortBy_BRIGADE_SORT_BY_STATUS:
		return models.BrigadeSortByStatus
	default:
		return ""
	}
}

// FromProtoSortOrder преобразует ASC или DESC в доменный порядок;
// неизвестное значение возвращает как пустую строку.
func FromProtoSortOrder(order brigadev1.SortOrder) models.SortOrder {
	switch order {
	case brigadev1.SortOrder_SORT_ORDER_ASC:
		return models.SortOrderAsc
	case brigadev1.SortOrder_SORT_ORDER_DESC:
		return models.SortOrderDesc
	default:
		return ""
	}
}

// ToProtoTimestamp преобразует время в protobuf; нулевое время даёт nil.
func ToProtoTimestamp(t time.Time) *timestamppb.Timestamp {

	if t.IsZero() {
		return nil
	}

	return timestamppb.New(t)
}

// ToProtoTimestampPtr преобразует необязательное время в protobuf;
// nil и указатель на нулевое время дают nil.
func ToProtoTimestampPtr(t *time.Time) *timestamppb.Timestamp {

	if t == nil || t.IsZero() {
		return nil
	}

	return timestamppb.New(*t)
}

// FromProtoTimestamp преобразует timestamp в указатель time.Time;
// nil сохраняет как nil без дополнительной проверки корректности timestamp.
func FromProtoTimestamp(ts *timestamppb.Timestamp) *time.Time {

	if ts == nil {
		return nil
	}

	t := ts.AsTime()
	return &t
}

// ToProtoBrigade преобразует бригаду, статус и даты в protobuf;
// отсутствующая специализация даёт пустую строку, nil бригада — nil.
func ToProtoBrigade(brigade *models.Brigade) *brigadev1.Brigade {

	if brigade == nil {
		return nil
	}

	specialization := ""

	if brigade.Specialization != nil {
		specialization = *brigade.Specialization
	}

	return &brigadev1.Brigade{
		Id:             brigade.ID.String(),
		DepartmentId:   brigade.DepartmentID.String(),
		Name:           brigade.Name,
		Description:    brigade.Description,
		Status:         ToProtoBrigadeStatus(brigade.Status),
		Specialization: specialization,
		CreatedAt:      ToProtoTimestamp(brigade.CreatedAt),
		UpdatedAt:      ToProtoTimestamp(brigade.UpdatedAt),
		DeactivatedAt:  ToProtoTimestampPtr(brigade.DeactivatedAt),
		ArchivedAt:     ToProtoTimestampPtr(brigade.ArchivedAt),
	}
}

// ToProtoBrigadeMember преобразует участника, роль, доступность и даты в protobuf;
// отсутствующий профиль даёт пустую строку, nil участник — nil.
func ToProtoBrigadeMember(member *models.BrigadeMember) *brigadev1.BrigadeMember {

	if member == nil {
		return nil
	}

	profileID := ""

	if member.ProfileID != nil {
		profileID = member.ProfileID.String()
	}

	return &brigadev1.BrigadeMember{
		Id:                          member.ID.String(),
		BrigadeId:                   member.BrigadeID.String(),
		UserId:                      member.UserID.String(),
		ProfileId:                   profileID,
		Role:                        ToProtoMemberRole(member.Role),
		Active:                      member.Active,
		AvailabilityStatus:          ToProtoMemberAvailabilityStatus(member.AvailabilityStatus),
		AvailabilityStatusChangedAt: ToProtoTimestamp(member.AvailabilityStatusChangedAt),
		JoinedAt:                    ToProtoTimestamp(member.JoinedAt),
		LeftAt:                      ToProtoTimestampPtr(member.LeftAt),
		CreatedAt:                   ToProtoTimestamp(member.CreatedAt),
		UpdatedAt:                   ToProtoTimestamp(member.UpdatedAt),
	}
}

// ToProtoSkill преобразует навык каталога с активностью и датами в protobuf;
// nil сохраняет как nil.
func ToProtoSkill(skill *models.Skill) *brigadev1.Skill {

	if skill == nil {
		return nil
	}

	return &brigadev1.Skill{
		Id:          skill.ID.String(),
		Code:        skill.Code,
		Name:        skill.Name,
		Description: skill.Description,
		Active:      skill.Active,
		CreatedAt:   ToProtoTimestamp(skill.CreatedAt),
		UpdatedAt:   ToProtoTimestamp(skill.UpdatedAt),
	}
}

// ToProtoBrigadeSkill преобразует связь бригады с навыком и вложенные данные
// каталога в protobuf; nil сохраняет как nil.
func ToProtoBrigadeSkill(skill *models.BrigadeSkill) *brigadev1.BrigadeSkill {

	if skill == nil {
		return nil
	}

	return &brigadev1.BrigadeSkill{
		Id:        skill.ID.String(),
		BrigadeId: skill.BrigadeID.String(),
		Skill:     ToProtoSkill(skill.Skill),
		Active:    skill.Active,
		CreatedAt: ToProtoTimestamp(skill.CreatedAt),
		UpdatedAt: ToProtoTimestamp(skill.UpdatedAt),
	}
}

// ToProtoBrigadeSchedule преобразует расписание в protobuf с часовым поясом
// и датами действия в формате YYYY-MM-DD; nil сохраняет как nil.
func ToProtoBrigadeSchedule(schedule *models.BrigadeSchedule) *brigadev1.BrigadeSchedule {

	if schedule == nil {
		return nil
	}

	return &brigadev1.BrigadeSchedule{
		Id:        schedule.ID.String(),
		BrigadeId: schedule.BrigadeID.String(),
		DayOfWeek: int32(schedule.DayOfWeek),
		StartsAt:  schedule.StartsAt,
		EndsAt:    schedule.EndsAt,
		Timezone:  schedule.Timezone,
		Active:    schedule.Active,
		ValidFrom: formatDatePtr(schedule.ValidFrom),
		ValidTo:   formatDatePtr(schedule.ValidTo),
		CreatedAt: ToProtoTimestamp(schedule.CreatedAt),
		UpdatedAt: ToProtoTimestamp(schedule.UpdatedAt),
	}
}

// ToProtoBrigadeZone преобразует зону с ведомством, GeoJSON, приоритетом,
// активностью и датами в protobuf; для nil возвращает nil.
func ToProtoBrigadeZone(zone *models.BrigadeZone) *brigadev1.BrigadeZone {

	if zone == nil {
		return nil
	}

	return &brigadev1.BrigadeZone{
		Id:           zone.ID.String(),
		BrigadeId:    zone.BrigadeID.String(),
		DepartmentId: zone.DepartmentID.String(),
		Name:         zone.Name,
		GeoJson:      zone.GeoJSON,
		Priority:     zone.Priority,
		Active:       zone.Active,
		CreatedAt:    ToProtoTimestamp(zone.CreatedAt),
		UpdatedAt:    ToProtoTimestamp(zone.UpdatedAt),
	}
}

// ToProtoBrigadeStatusHistory преобразует переход статуса бригады в protobuf;
// отсутствующий исходный статус даёт UNSPECIFIED, автор и request ID — пустые строки.
// nil запись сохраняется как nil.
func ToProtoBrigadeStatusHistory(item *models.BrigadeStatusHistory) *brigadev1.BrigadeStatusHistory {

	if item == nil {
		return nil
	}

	fromStatus := brigadev1.BrigadeStatus_BRIGADE_STATUS_UNSPECIFIED

	if item.FromStatus != nil {
		fromStatus = ToProtoBrigadeStatus(*item.FromStatus)
	}

	changedByUserID := ""

	if item.ChangedByUserID != nil {
		changedByUserID = item.ChangedByUserID.String()
	}

	requestID := ""

	if item.RequestID != nil {
		requestID = *item.RequestID
	}

	return &brigadev1.BrigadeStatusHistory{
		Id:              item.ID.String(),
		BrigadeId:       item.BrigadeID.String(),
		FromStatus:      fromStatus,
		ToStatus:        ToProtoBrigadeStatus(item.ToStatus),
		Reason:          item.Reason,
		ChangedByUserId: changedByUserID,
		RequestId:       requestID,
		CreatedAt:       ToProtoTimestamp(item.CreatedAt),
	}
}

// ToProtoBrigadeMemberHistory преобразует историю состава в protobuf;
// отсутствующие роли даёт как UNSPECIFIED, необязательные ID — как пустые строки,
// nil запись — как nil.
func ToProtoBrigadeMemberHistory(item *models.BrigadeMemberHistory) *brigadev1.BrigadeMemberHistory {

	if item == nil {
		return nil
	}

	memberID := ""

	if item.MemberID != nil {
		memberID = item.MemberID.String()
	}

	profileID := ""

	if item.ProfileID != nil {
		profileID = item.ProfileID.String()
	}

	oldRole := brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_UNSPECIFIED

	if item.OldRole != nil {
		oldRole = ToProtoMemberRole(*item.OldRole)
	}

	newRole := brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_UNSPECIFIED

	if item.NewRole != nil {
		newRole = ToProtoMemberRole(*item.NewRole)
	}

	changedByUserID := ""

	if item.ChangedByUserID != nil {
		changedByUserID = item.ChangedByUserID.String()
	}

	requestID := ""

	if item.RequestID != nil {
		requestID = *item.RequestID
	}

	return &brigadev1.BrigadeMemberHistory{
		Id:              item.ID.String(),
		BrigadeId:       item.BrigadeID.String(),
		MemberId:        memberID,
		UserId:          item.UserID.String(),
		ProfileId:       profileID,
		Action:          ToProtoMemberHistoryAction(item.Action),
		OldRole:         oldRole,
		NewRole:         newRole,
		ChangedByUserId: changedByUserID,
		RequestId:       requestID,
		CreatedAt:       ToProtoTimestamp(item.CreatedAt),
	}
}

// ToProtoBrigadeMemberStatusHistory преобразует переход доступности участника
// в protobuf; отсутствующий исходный статус даёт UNSPECIFIED, необязательные ID —
// пустые строки. nil запись сохраняется как nil.
func ToProtoBrigadeMemberStatusHistory(item *models.BrigadeMemberStatusHistory) *brigadev1.BrigadeMemberStatusHistory {

	if item == nil {
		return nil
	}

	memberID := ""

	if item.MemberID != nil {
		memberID = item.MemberID.String()
	}

	fromStatus := brigadev1.BrigadeMemberAvailabilityStatus_BRIGADE_MEMBER_AVAILABILITY_STATUS_UNSPECIFIED

	if item.FromStatus != nil {
		fromStatus = ToProtoMemberAvailabilityStatus(*item.FromStatus)
	}

	changedByUserID := ""

	if item.ChangedByUserID != nil {
		changedByUserID = item.ChangedByUserID.String()
	}

	requestID := ""

	if item.RequestID != nil {
		requestID = *item.RequestID
	}

	return &brigadev1.BrigadeMemberStatusHistory{
		Id:              item.ID.String(),
		BrigadeId:       item.BrigadeID.String(),
		MemberId:        memberID,
		UserId:          item.UserID.String(),
		FromStatus:      fromStatus,
		ToStatus:        ToProtoMemberAvailabilityStatus(item.ToStatus),
		Reason:          item.Reason,
		ChangedByUserId: changedByUserID,
		RequestId:       requestID,
		CreatedAt:       ToProtoTimestamp(item.CreatedAt),
	}
}

// formatDatePtr форматирует дату как YYYY-MM-DD; nil и нулевое время дают пустую строку.
func formatDatePtr(t *time.Time) string {

	if t == nil || t.IsZero() {
		return ""
	}

	return t.Format(time.DateOnly)
}
