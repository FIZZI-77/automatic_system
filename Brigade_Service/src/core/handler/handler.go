package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"brigade/models"
	"brigade/pkg"
	"brigade/src/core/service"
)

type BrigadeHandler struct {
	brigadev1.UnimplementedBrigadeServiceServer
	service *service.Service
	logger  *zap.Logger
}

func NewBrigadeHandler(service *service.Service, logger *zap.Logger) *BrigadeHandler {
	return &BrigadeHandler{
		service: service,
		logger:  logger,
	}
}

type actorContext struct {
	UserID       *uuid.UUID
	DepartmentID *uuid.UUID
	Roles        []string
}

func (h *BrigadeHandler) CreateBrigade(ctx context.Context, req *brigadev1.CreateBrigadeRequest) (*brigadev1.CreateBrigadeResponse, error) {
	logger := h.requestLogger(ctx, "CreateBrigade")

	departmentID, err := parseUUID(req.GetDepartmentId(), "department_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "CreateBrigade", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.CreateBrigade(ctx, &models.CreateBrigadeInput{
		DepartmentID:      departmentID,
		Name:              req.GetName(),
		Description:       req.GetDescription(),
		Specialization:    optionalString(req.GetSpecialization()),
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "CreateBrigade", err)
	}

	return &brigadev1.CreateBrigadeResponse{Brigade: ToProtoBrigade(res.Brigade)}, nil
}

func (h *BrigadeHandler) GetBrigadeByID(ctx context.Context, req *brigadev1.GetBrigadeByIDRequest) (*brigadev1.GetBrigadeByIDResponse, error) {
	logger := h.requestLogger(ctx, "GetBrigadeByID")

	id, err := parseUUID(req.GetId(), "id")
	if err != nil {
		return nil, h.logAndMapError(logger, "GetBrigadeByID", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{
		ID:                id,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "GetBrigadeByID", err)
	}

	return &brigadev1.GetBrigadeByIDResponse{Brigade: ToProtoBrigade(res.Brigade)}, nil
}

func (h *BrigadeHandler) ListBrigades(ctx context.Context, req *brigadev1.ListBrigadesRequest) (*brigadev1.ListBrigadesResponse, error) {
	logger := h.requestLogger(ctx, "ListBrigades")

	departmentID, err := parseOptionalUUIDPtr(req.DepartmentId, "department_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "ListBrigades", err)
	}

	var brigadeStatus *models.BrigadeStatus
	if req.Status != nil && req.GetStatus() != brigadev1.BrigadeStatus_BRIGADE_STATUS_UNSPECIFIED {
		value := FromProtoBrigadeStatus(req.GetStatus())
		brigadeStatus = &value
	}

	var sortBy models.BrigadeSortBy
	if req.SortBy != nil {
		sortBy = FromProtoBrigadeSortBy(req.GetSortBy())
	}

	var sortOrder models.SortOrder
	if req.SortOrder != nil {
		sortOrder = FromProtoSortOrder(req.GetSortOrder())
	}

	actor := actorFromContext(ctx)
	res, err := h.service.ListBrigades(ctx, &models.ListBrigadesInput{
		DepartmentID:      departmentID,
		Status:            brigadeStatus,
		Specialization:    req.Specialization,
		CreatedFrom:       FromProtoTimestamp(req.GetCreatedFrom()),
		CreatedTo:         FromProtoTimestamp(req.GetCreatedTo()),
		SortBy:            sortBy,
		SortOrder:         sortOrder,
		Limit:             req.GetLimit(),
		Offset:            req.GetOffset(),
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "ListBrigades", err)
	}

	return &brigadev1.ListBrigadesResponse{
		Brigades: toProtoBrigades(res.Brigades),
		Total:    res.Total,
	}, nil
}

func (h *BrigadeHandler) UpdateBrigade(ctx context.Context, req *brigadev1.UpdateBrigadeRequest) (*brigadev1.UpdateBrigadeResponse, error) {
	logger := h.requestLogger(ctx, "UpdateBrigade")

	id, err := parseUUID(req.GetId(), "id")
	if err != nil {
		return nil, h.logAndMapError(logger, "UpdateBrigade", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.UpdateBrigade(ctx, &models.UpdateBrigadeInput{
		ID:                id,
		Name:              req.Name,
		Description:       req.Description,
		Specialization:    req.Specialization,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "UpdateBrigade", err)
	}

	return &brigadev1.UpdateBrigadeResponse{Brigade: ToProtoBrigade(res.Brigade)}, nil
}

func (h *BrigadeHandler) DeactivateBrigade(ctx context.Context, req *brigadev1.DeactivateBrigadeRequest) (*brigadev1.DeactivateBrigadeResponse, error) {
	logger := h.requestLogger(ctx, "DeactivateBrigade")

	id, changedBy, err := parseIDAndChangedBy(req.GetId(), req.GetChangedByUserId())
	if err != nil {
		return nil, h.logAndMapError(logger, "DeactivateBrigade", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.DeactivateBrigade(ctx, &models.DeactivateBrigadeInput{
		ID:                id,
		Reason:            req.GetReason(),
		ChangedByUserID:   changedBy,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "DeactivateBrigade", err)
	}

	return &brigadev1.DeactivateBrigadeResponse{Brigade: ToProtoBrigade(res.Brigade)}, nil
}

func (h *BrigadeHandler) ArchiveBrigade(ctx context.Context, req *brigadev1.ArchiveBrigadeRequest) (*brigadev1.ArchiveBrigadeResponse, error) {
	logger := h.requestLogger(ctx, "ArchiveBrigade")

	id, changedBy, err := parseIDAndChangedBy(req.GetId(), req.GetChangedByUserId())
	if err != nil {
		return nil, h.logAndMapError(logger, "ArchiveBrigade", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.ArchiveBrigade(ctx, &models.ArchiveBrigadeInput{
		ID:                id,
		Reason:            req.GetReason(),
		ChangedByUserID:   changedBy,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "ArchiveBrigade", err)
	}

	return &brigadev1.ArchiveBrigadeResponse{Brigade: ToProtoBrigade(res.Brigade)}, nil
}

func (h *BrigadeHandler) SetBrigadeStatus(ctx context.Context, req *brigadev1.SetBrigadeStatusRequest) (*brigadev1.SetBrigadeStatusResponse, error) {
	logger := h.requestLogger(ctx, "SetBrigadeStatus")

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "SetBrigadeStatus", err)
	}
	changedBy, err := parseOptionalUUID(req.GetChangedByUserId(), "changed_by_user_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "SetBrigadeStatus", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.SetBrigadeStatus(ctx, &models.SetBrigadeStatusInput{
		BrigadeID:         brigadeID,
		Status:            FromProtoBrigadeStatus(req.GetStatus()),
		Reason:            req.GetReason(),
		ChangedByUserID:   changedBy,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "SetBrigadeStatus", err)
	}

	return &brigadev1.SetBrigadeStatusResponse{Brigade: ToProtoBrigade(res.Brigade)}, nil
}

func (h *BrigadeHandler) GetBrigadeStatusHistory(ctx context.Context, req *brigadev1.GetBrigadeStatusHistoryRequest) (*brigadev1.GetBrigadeStatusHistoryResponse, error) {
	logger := h.requestLogger(ctx, "GetBrigadeStatusHistory")

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "GetBrigadeStatusHistory", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.GetBrigadeStatusHistory(ctx, &models.GetBrigadeStatusHistoryInput{
		BrigadeID:         brigadeID,
		Limit:             req.GetLimit(),
		Offset:            req.GetOffset(),
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "GetBrigadeStatusHistory", err)
	}

	history := make([]*brigadev1.BrigadeStatusHistory, 0, len(res.History))
	for _, item := range res.History {
		history = append(history, ToProtoBrigadeStatusHistory(item))
	}

	return &brigadev1.GetBrigadeStatusHistoryResponse{History: history, Total: res.Total}, nil
}

func (h *BrigadeHandler) AddBrigadeMember(ctx context.Context, req *brigadev1.AddBrigadeMemberRequest) (*brigadev1.AddBrigadeMemberResponse, error) {
	logger := h.requestLogger(ctx, "AddBrigadeMember")

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "AddBrigadeMember", err)
	}
	userID, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "AddBrigadeMember", err)
	}
	profileID, err := parseOptionalUUIDPtr(req.ProfileId, "profile_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "AddBrigadeMember", err)
	}
	changedBy, err := parseOptionalUUID(req.GetChangedByUserId(), "changed_by_user_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "AddBrigadeMember", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.AddBrigadeMember(ctx, &models.AddBrigadeMemberInput{
		BrigadeID:         brigadeID,
		UserID:            userID,
		ProfileID:         profileID,
		Role:              FromProtoMemberRole(req.GetRole()),
		ChangedByUserID:   changedBy,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "AddBrigadeMember", err)
	}

	return &brigadev1.AddBrigadeMemberResponse{Member: ToProtoBrigadeMember(res.Member)}, nil
}

func (h *BrigadeHandler) RemoveBrigadeMember(ctx context.Context, req *brigadev1.RemoveBrigadeMemberRequest) (*brigadev1.RemoveBrigadeMemberResponse, error) {
	logger := h.requestLogger(ctx, "RemoveBrigadeMember")

	brigadeID, memberID, changedBy, err := parseBrigadeMemberChangedBy(req.GetBrigadeId(), req.GetMemberId(), req.GetChangedByUserId())
	if err != nil {
		return nil, h.logAndMapError(logger, "RemoveBrigadeMember", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.RemoveBrigadeMember(ctx, &models.RemoveBrigadeMemberInput{
		BrigadeID:         brigadeID,
		MemberID:          memberID,
		Reason:            req.GetReason(),
		ChangedByUserID:   changedBy,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "RemoveBrigadeMember", err)
	}

	return &brigadev1.RemoveBrigadeMemberResponse{Member: ToProtoBrigadeMember(res.Member)}, nil
}

func (h *BrigadeHandler) ChangeBrigadeMemberRole(ctx context.Context, req *brigadev1.ChangeBrigadeMemberRoleRequest) (*brigadev1.ChangeBrigadeMemberRoleResponse, error) {
	logger := h.requestLogger(ctx, "ChangeBrigadeMemberRole")

	brigadeID, memberID, changedBy, err := parseBrigadeMemberChangedBy(req.GetBrigadeId(), req.GetMemberId(), req.GetChangedByUserId())
	if err != nil {
		return nil, h.logAndMapError(logger, "ChangeBrigadeMemberRole", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.ChangeBrigadeMemberRole(ctx, &models.ChangeBrigadeMemberRoleInput{
		BrigadeID:         brigadeID,
		MemberID:          memberID,
		Role:              FromProtoMemberRole(req.GetRole()),
		ChangedByUserID:   changedBy,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "ChangeBrigadeMemberRole", err)
	}

	return &brigadev1.ChangeBrigadeMemberRoleResponse{Member: ToProtoBrigadeMember(res.Member)}, nil
}

func (h *BrigadeHandler) SetBrigadeMemberAvailability(ctx context.Context, req *brigadev1.SetBrigadeMemberAvailabilityRequest) (*brigadev1.SetBrigadeMemberAvailabilityResponse, error) {
	logger := h.requestLogger(ctx, "SetBrigadeMemberAvailability")

	brigadeID, memberID, changedBy, err := parseBrigadeMemberChangedBy(req.GetBrigadeId(), req.GetMemberId(), req.GetChangedByUserId())
	if err != nil {
		return nil, h.logAndMapError(logger, "SetBrigadeMemberAvailability", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.SetBrigadeMemberAvailability(ctx, &models.SetBrigadeMemberAvailabilityInput{
		BrigadeID:         brigadeID,
		MemberID:          memberID,
		Status:            FromProtoMemberAvailabilityStatus(req.GetStatus()),
		Reason:            req.GetReason(),
		ChangedByUserID:   changedBy,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "SetBrigadeMemberAvailability", err)
	}

	return &brigadev1.SetBrigadeMemberAvailabilityResponse{Member: ToProtoBrigadeMember(res.Member)}, nil
}

func (h *BrigadeHandler) ListBrigadeMembers(ctx context.Context, req *brigadev1.ListBrigadeMembersRequest) (*brigadev1.ListBrigadeMembersResponse, error) {
	logger := h.requestLogger(ctx, "ListBrigadeMembers")

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "ListBrigadeMembers", err)
	}

	var role *models.BrigadeMemberRole
	if req.Role != nil && req.GetRole() != brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_UNSPECIFIED {
		value := FromProtoMemberRole(req.GetRole())
		role = &value
	}

	var availability *models.BrigadeMemberAvailabilityStatus
	if req.AvailabilityStatus != nil && req.GetAvailabilityStatus() != brigadev1.BrigadeMemberAvailabilityStatus_BRIGADE_MEMBER_AVAILABILITY_STATUS_UNSPECIFIED {
		value := FromProtoMemberAvailabilityStatus(req.GetAvailabilityStatus())
		availability = &value
	}

	actor := actorFromContext(ctx)
	res, err := h.service.ListBrigadeMembers(ctx, &models.ListBrigadeMembersInput{
		BrigadeID:          brigadeID,
		Active:             req.Active,
		Role:               role,
		AvailabilityStatus: availability,
		Limit:              req.GetLimit(),
		Offset:             req.GetOffset(),
		ActorUserID:        actor.UserID,
		ActorDepartmentID:  actor.DepartmentID,
		ActorRoles:         actor.Roles,
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "ListBrigadeMembers", err)
	}

	return &brigadev1.ListBrigadeMembersResponse{Members: toProtoMembers(res.Members), Total: res.Total}, nil
}

func (h *BrigadeHandler) GetBrigadeMemberHistory(ctx context.Context, req *brigadev1.GetBrigadeMemberHistoryRequest) (*brigadev1.GetBrigadeMemberHistoryResponse, error) {
	logger := h.requestLogger(ctx, "GetBrigadeMemberHistory")

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "GetBrigadeMemberHistory", err)
	}
	memberID, err := parseOptionalUUIDPtr(req.MemberId, "member_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "GetBrigadeMemberHistory", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.GetBrigadeMemberHistory(ctx, &models.GetBrigadeMemberHistoryInput{
		BrigadeID:         brigadeID,
		MemberID:          memberID,
		Limit:             req.GetLimit(),
		Offset:            req.GetOffset(),
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "GetBrigadeMemberHistory", err)
	}

	history := make([]*brigadev1.BrigadeMemberHistory, 0, len(res.History))
	for _, item := range res.History {
		history = append(history, ToProtoBrigadeMemberHistory(item))
	}

	return &brigadev1.GetBrigadeMemberHistoryResponse{History: history, Total: res.Total}, nil
}

func (h *BrigadeHandler) GetBrigadeMemberStatusHistory(ctx context.Context, req *brigadev1.GetBrigadeMemberStatusHistoryRequest) (*brigadev1.GetBrigadeMemberStatusHistoryResponse, error) {
	logger := h.requestLogger(ctx, "GetBrigadeMemberStatusHistory")

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "GetBrigadeMemberStatusHistory", err)
	}
	memberID, err := parseOptionalUUIDPtr(req.MemberId, "member_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "GetBrigadeMemberStatusHistory", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.GetBrigadeMemberStatusHistory(ctx, &models.GetBrigadeMemberStatusHistoryInput{
		BrigadeID:         brigadeID,
		MemberID:          memberID,
		Limit:             req.GetLimit(),
		Offset:            req.GetOffset(),
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "GetBrigadeMemberStatusHistory", err)
	}

	history := make([]*brigadev1.BrigadeMemberStatusHistory, 0, len(res.History))
	for _, item := range res.History {
		history = append(history, ToProtoBrigadeMemberStatusHistory(item))
	}

	return &brigadev1.GetBrigadeMemberStatusHistoryResponse{History: history, Total: res.Total}, nil
}

func (h *BrigadeHandler) GetBrigadeByUserID(ctx context.Context, req *brigadev1.GetBrigadeByUserIDRequest) (*brigadev1.GetBrigadeByUserIDResponse, error) {
	logger := h.requestLogger(ctx, "GetBrigadeByUserID")

	userID, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "GetBrigadeByUserID", err)
	}

	res, err := h.service.GetBrigadeByUserID(ctx, &models.GetBrigadeByUserIDInput{
		UserID:     userID,
		OnlyActive: req.GetOnlyActive(),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "GetBrigadeByUserID", err)
	}

	return &brigadev1.GetBrigadeByUserIDResponse{
		Brigade: ToProtoBrigade(res.Brigade),
		Member:  ToProtoBrigadeMember(res.Member),
	}, nil
}

func (h *BrigadeHandler) CreateSkill(ctx context.Context, req *brigadev1.CreateSkillRequest) (*brigadev1.CreateSkillResponse, error) {
	logger := h.requestLogger(ctx, "CreateSkill")

	actor := actorFromContext(ctx)
	res, err := h.service.CreateSkill(ctx, &models.CreateSkillInput{
		Code:        req.GetCode(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		ActorUserID: actor.UserID,
		ActorRoles:  actor.Roles,
		RequestID:   requestIDFromContext(ctx),
		TraceID:     traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "CreateSkill", err)
	}

	return &brigadev1.CreateSkillResponse{Skill: ToProtoSkill(res.Skill)}, nil
}

func (h *BrigadeHandler) UpdateSkill(ctx context.Context, req *brigadev1.UpdateSkillRequest) (*brigadev1.UpdateSkillResponse, error) {
	logger := h.requestLogger(ctx, "UpdateSkill")

	id, err := parseUUID(req.GetId(), "id")
	if err != nil {
		return nil, h.logAndMapError(logger, "UpdateSkill", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.UpdateSkill(ctx, &models.UpdateSkillInput{
		ID:          id,
		Code:        req.Code,
		Name:        req.Name,
		Description: req.Description,
		Active:      req.Active,
		ActorUserID: actor.UserID,
		ActorRoles:  actor.Roles,
		RequestID:   requestIDFromContext(ctx),
		TraceID:     traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "UpdateSkill", err)
	}

	return &brigadev1.UpdateSkillResponse{Skill: ToProtoSkill(res.Skill)}, nil
}

func (h *BrigadeHandler) DeactivateSkill(ctx context.Context, req *brigadev1.DeactivateSkillRequest) (*brigadev1.DeactivateSkillResponse, error) {
	logger := h.requestLogger(ctx, "DeactivateSkill")

	id, err := parseUUID(req.GetId(), "id")
	if err != nil {
		return nil, h.logAndMapError(logger, "DeactivateSkill", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.DeactivateSkill(ctx, &models.DeactivateSkillInput{
		ID:          id,
		ActorUserID: actor.UserID,
		ActorRoles:  actor.Roles,
		RequestID:   requestIDFromContext(ctx),
		TraceID:     traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "DeactivateSkill", err)
	}

	return &brigadev1.DeactivateSkillResponse{Skill: ToProtoSkill(res.Skill)}, nil
}

func (h *BrigadeHandler) ListSkills(ctx context.Context, req *brigadev1.ListSkillsRequest) (*brigadev1.ListSkillsResponse, error) {
	logger := h.requestLogger(ctx, "ListSkills")

	actor := actorFromContext(ctx)
	res, err := h.service.ListSkills(ctx, &models.ListSkillsInput{
		Active:      req.Active,
		Query:       req.Query,
		Limit:       req.GetLimit(),
		Offset:      req.GetOffset(),
		ActorUserID: actor.UserID,
		ActorRoles:  actor.Roles,
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "ListSkills", err)
	}

	skills := make([]*brigadev1.Skill, 0, len(res.Skills))
	for _, item := range res.Skills {
		skills = append(skills, ToProtoSkill(item))
	}

	return &brigadev1.ListSkillsResponse{Skills: skills, Total: res.Total}, nil
}

func (h *BrigadeHandler) AddBrigadeSkill(ctx context.Context, req *brigadev1.AddBrigadeSkillRequest) (*brigadev1.AddBrigadeSkillResponse, error) {
	logger := h.requestLogger(ctx, "AddBrigadeSkill")

	brigadeID, skillID, err := parseBrigadeSkillIDs(req.GetBrigadeId(), req.GetSkillId())
	if err != nil {
		return nil, h.logAndMapError(logger, "AddBrigadeSkill", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.AddBrigadeSkill(ctx, &models.AddBrigadeSkillInput{
		BrigadeID:         brigadeID,
		SkillID:           skillID,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "AddBrigadeSkill", err)
	}

	return &brigadev1.AddBrigadeSkillResponse{BrigadeSkill: ToProtoBrigadeSkill(res.BrigadeSkill)}, nil
}

func (h *BrigadeHandler) RemoveBrigadeSkill(ctx context.Context, req *brigadev1.RemoveBrigadeSkillRequest) (*brigadev1.RemoveBrigadeSkillResponse, error) {
	logger := h.requestLogger(ctx, "RemoveBrigadeSkill")

	brigadeID, skillID, err := parseBrigadeSkillIDs(req.GetBrigadeId(), req.GetSkillId())
	if err != nil {
		return nil, h.logAndMapError(logger, "RemoveBrigadeSkill", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.RemoveBrigadeSkill(ctx, &models.RemoveBrigadeSkillInput{
		BrigadeID:         brigadeID,
		SkillID:           skillID,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "RemoveBrigadeSkill", err)
	}

	return &brigadev1.RemoveBrigadeSkillResponse{BrigadeSkill: ToProtoBrigadeSkill(res.BrigadeSkill)}, nil
}

func (h *BrigadeHandler) ListBrigadeSkills(ctx context.Context, req *brigadev1.ListBrigadeSkillsRequest) (*brigadev1.ListBrigadeSkillsResponse, error) {
	logger := h.requestLogger(ctx, "ListBrigadeSkills")

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "ListBrigadeSkills", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.ListBrigadeSkills(ctx, &models.ListBrigadeSkillsInput{
		BrigadeID:         brigadeID,
		Active:            req.Active,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "ListBrigadeSkills", err)
	}

	skills := make([]*brigadev1.BrigadeSkill, 0, len(res.Skills))
	for _, item := range res.Skills {
		skills = append(skills, ToProtoBrigadeSkill(item))
	}

	return &brigadev1.ListBrigadeSkillsResponse{Skills: skills}, nil
}

func (h *BrigadeHandler) SetBrigadeSchedule(ctx context.Context, req *brigadev1.SetBrigadeScheduleRequest) (*brigadev1.SetBrigadeScheduleResponse, error) {
	logger := h.requestLogger(ctx, "SetBrigadeSchedule")

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "SetBrigadeSchedule", err)
	}
	items, err := fromProtoScheduleItems(req.GetItems())
	if err != nil {
		return nil, h.logAndMapError(logger, "SetBrigadeSchedule", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.SetBrigadeSchedule(ctx, &models.SetBrigadeScheduleInput{
		BrigadeID:         brigadeID,
		Items:             items,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "SetBrigadeSchedule", err)
	}

	return &brigadev1.SetBrigadeScheduleResponse{Schedule: toProtoSchedule(res.Schedule)}, nil
}

func (h *BrigadeHandler) ListBrigadeSchedule(ctx context.Context, req *brigadev1.ListBrigadeScheduleRequest) (*brigadev1.ListBrigadeScheduleResponse, error) {
	logger := h.requestLogger(ctx, "ListBrigadeSchedule")

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "ListBrigadeSchedule", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.ListBrigadeSchedule(ctx, &models.ListBrigadeScheduleInput{
		BrigadeID:         brigadeID,
		Active:            req.Active,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "ListBrigadeSchedule", err)
	}

	return &brigadev1.ListBrigadeScheduleResponse{Schedule: toProtoSchedule(res.Schedule)}, nil
}

func (h *BrigadeHandler) CreateBrigadeZone(ctx context.Context, req *brigadev1.CreateBrigadeZoneRequest) (*brigadev1.CreateBrigadeZoneResponse, error) {
	logger := h.requestLogger(ctx, "CreateBrigadeZone")

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "CreateBrigadeZone", err)
	}
	departmentID, err := parseUUID(req.GetDepartmentId(), "department_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "CreateBrigadeZone", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.CreateBrigadeZone(ctx, &models.CreateBrigadeZoneInput{
		BrigadeID:         brigadeID,
		DepartmentID:      departmentID,
		Name:              req.GetName(),
		GeoJSON:           req.GetGeoJson(),
		Priority:          req.GetPriority(),
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "CreateBrigadeZone", err)
	}

	return &brigadev1.CreateBrigadeZoneResponse{Zone: ToProtoBrigadeZone(res.Zone)}, nil
}

func (h *BrigadeHandler) UpdateBrigadeZone(ctx context.Context, req *brigadev1.UpdateBrigadeZoneRequest) (*brigadev1.UpdateBrigadeZoneResponse, error) {
	logger := h.requestLogger(ctx, "UpdateBrigadeZone")

	id, err := parseUUID(req.GetId(), "id")
	if err != nil {
		return nil, h.logAndMapError(logger, "UpdateBrigadeZone", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.UpdateBrigadeZone(ctx, &models.UpdateBrigadeZoneInput{
		ID:                id,
		Name:              req.Name,
		GeoJSON:           req.GeoJson,
		Priority:          req.Priority,
		Active:            req.Active,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "UpdateBrigadeZone", err)
	}

	return &brigadev1.UpdateBrigadeZoneResponse{Zone: ToProtoBrigadeZone(res.Zone)}, nil
}

func (h *BrigadeHandler) DeleteBrigadeZone(ctx context.Context, req *brigadev1.DeleteBrigadeZoneRequest) (*brigadev1.DeleteBrigadeZoneResponse, error) {
	logger := h.requestLogger(ctx, "DeleteBrigadeZone")

	id, err := parseUUID(req.GetId(), "id")
	if err != nil {
		return nil, h.logAndMapError(logger, "DeleteBrigadeZone", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.DeleteBrigadeZone(ctx, &models.DeleteBrigadeZoneInput{
		ID:                id,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
		RequestID:         requestIDFromContext(ctx),
		TraceID:           traceIDFromContext(ctx),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "DeleteBrigadeZone", err)
	}

	return &brigadev1.DeleteBrigadeZoneResponse{Zone: ToProtoBrigadeZone(res.Zone)}, nil
}

func (h *BrigadeHandler) ListBrigadeZones(ctx context.Context, req *brigadev1.ListBrigadeZonesRequest) (*brigadev1.ListBrigadeZonesResponse, error) {
	logger := h.requestLogger(ctx, "ListBrigadeZones")

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "ListBrigadeZones", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.ListBrigadeZones(ctx, &models.ListBrigadeZonesInput{
		BrigadeID:         brigadeID,
		Active:            req.Active,
		ActorUserID:       actor.UserID,
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "ListBrigadeZones", err)
	}

	return &brigadev1.ListBrigadeZonesResponse{Zones: toProtoZones(res.Zones)}, nil
}

func (h *BrigadeHandler) CheckBrigadeCoversPoint(ctx context.Context, req *brigadev1.CheckBrigadeCoversPointRequest) (*brigadev1.CheckBrigadeCoversPointResponse, error) {
	logger := h.requestLogger(ctx, "CheckBrigadeCoversPoint")

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "CheckBrigadeCoversPoint", err)
	}

	res, err := h.service.CheckBrigadeCoversPoint(ctx, &models.CheckBrigadeCoversPointInput{
		BrigadeID: brigadeID,
		Longitude: req.GetLongitude(),
		Latitude:  req.GetLatitude(),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "CheckBrigadeCoversPoint", err)
	}

	return &brigadev1.CheckBrigadeCoversPointResponse{
		Covers:       res.Covers,
		MatchedZones: toProtoZones(res.MatchedZones),
	}, nil
}

func (h *BrigadeHandler) FindBrigadesByPoint(ctx context.Context, req *brigadev1.FindBrigadesByPointRequest) (*brigadev1.FindBrigadesByPointResponse, error) {
	logger := h.requestLogger(ctx, "FindBrigadesByPoint")

	departmentID, err := parseUUID(req.GetDepartmentId(), "department_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "FindBrigadesByPoint", err)
	}
	requiredSkills, err := parseUUIDSlice(req.GetRequiredSkillIds(), "required_skill_ids")
	if err != nil {
		return nil, h.logAndMapError(logger, "FindBrigadesByPoint", err)
	}

	res, err := h.service.FindBrigadesByPoint(ctx, &models.FindBrigadesByPointInput{
		DepartmentID:     departmentID,
		Longitude:        req.GetLongitude(),
		Latitude:         req.GetLatitude(),
		OnlyAvailable:    req.GetOnlyAvailable(),
		RequiredSkillIDs: requiredSkills,
		RequiredRoles:    fromProtoRequiredRoles(req.GetRequiredRoles()),
		Limit:            req.GetLimit(),
		Offset:           req.GetOffset(),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "FindBrigadesByPoint", err)
	}

	return &brigadev1.FindBrigadesByPointResponse{Brigades: toProtoBrigades(res.Brigades), Total: res.Total}, nil
}

func (h *BrigadeHandler) GetAvailableBrigades(ctx context.Context, req *brigadev1.GetAvailableBrigadesRequest) (*brigadev1.GetAvailableBrigadesResponse, error) {
	logger := h.requestLogger(ctx, "GetAvailableBrigades")

	departmentID, err := parseUUID(req.GetDepartmentId(), "department_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "GetAvailableBrigades", err)
	}
	requiredSkills, err := parseUUIDSlice(req.GetRequiredSkillIds(), "required_skill_ids")
	if err != nil {
		return nil, h.logAndMapError(logger, "GetAvailableBrigades", err)
	}

	res, err := h.service.GetAvailableBrigades(ctx, &models.GetAvailableBrigadesInput{
		DepartmentID:     departmentID,
		Longitude:        req.Longitude,
		Latitude:         req.Latitude,
		RequiredSkillIDs: requiredSkills,
		RequiredRoles:    fromProtoRequiredRoles(req.GetRequiredRoles()),
		Limit:            req.GetLimit(),
		Offset:           req.GetOffset(),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "GetAvailableBrigades", err)
	}

	return &brigadev1.GetAvailableBrigadesResponse{Brigades: toProtoBrigades(res.Brigades), Total: res.Total}, nil
}

func (h *BrigadeHandler) CheckBrigadeCanHandleTicket(ctx context.Context, req *brigadev1.CheckBrigadeCanHandleTicketRequest) (*brigadev1.CheckBrigadeCanHandleTicketResponse, error) {
	logger := h.requestLogger(ctx, "CheckBrigadeCanHandleTicket")

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "CheckBrigadeCanHandleTicket", err)
	}
	departmentID, err := parseUUID(req.GetDepartmentId(), "department_id")
	if err != nil {
		return nil, h.logAndMapError(logger, "CheckBrigadeCanHandleTicket", err)
	}
	requiredSkills, err := parseUUIDSlice(req.GetRequiredSkillIds(), "required_skill_ids")
	if err != nil {
		return nil, h.logAndMapError(logger, "CheckBrigadeCanHandleTicket", err)
	}

	res, err := h.service.CheckBrigadeCanHandleTicket(ctx, &models.CheckBrigadeCanHandleTicketInput{
		BrigadeID:        brigadeID,
		DepartmentID:     departmentID,
		Longitude:        req.GetLongitude(),
		Latitude:         req.GetLatitude(),
		RequiredSkillIDs: requiredSkills,
		RequiredRoles:    fromProtoRequiredRoles(req.GetRequiredRoles()),
	})
	if err != nil {
		return nil, h.logAndMapError(logger, "CheckBrigadeCanHandleTicket", err)
	}

	return &brigadev1.CheckBrigadeCanHandleTicketResponse{
		CanHandle: res.CanHandle,
		Reasons:   res.Reasons,
	}, nil
}

func (h *BrigadeHandler) requestLogger(ctx context.Context, method string) *zap.Logger {
	logger := h.logger.With(pkg.RequestIDField(ctx), zap.String("method", method))
	logger.Info("gRPC request received")
	return logger
}

func (h *BrigadeHandler) logAndMapError(logger *zap.Logger, method string, err error) error {
	logger.Warn("gRPC request failed", zap.Error(err))
	return brigadeStatusError(method, err)
}

func parseUUID(value string, field string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: invalid %s: %v", models.ErrValidation, field, err)
	}
	return parsed, nil
}

func parseOptionalUUID(value string, field string) (*uuid.UUID, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}

	parsed, err := parseUUID(value, field)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func parseOptionalUUIDPtr(value *string, field string) (*uuid.UUID, error) {
	if value == nil {
		return nil, nil
	}
	return parseOptionalUUID(*value, field)
}

func parseUUIDSlice(values []string, field string) ([]uuid.UUID, error) {
	result := make([]uuid.UUID, 0, len(values))
	for _, value := range values {
		parsed, err := parseUUID(value, field)
		if err != nil {
			return nil, err
		}
		result = append(result, parsed)
	}
	return result, nil
}

func fromProtoRequiredRoles(values []brigadev1.BrigadeMemberRole) []models.BrigadeMemberRole {
	result := make([]models.BrigadeMemberRole, 0, len(values))
	for _, value := range values {
		result = append(result, FromProtoMemberRole(value))
	}
	return result
}

func parseIDAndChangedBy(idValue string, changedByValue string) (uuid.UUID, *uuid.UUID, error) {
	id, err := parseUUID(idValue, "id")
	if err != nil {
		return uuid.Nil, nil, err
	}
	changedBy, err := parseOptionalUUID(changedByValue, "changed_by_user_id")
	if err != nil {
		return uuid.Nil, nil, err
	}
	return id, changedBy, nil
}

func parseBrigadeMemberChangedBy(brigadeIDValue string, memberIDValue string, changedByValue string) (uuid.UUID, uuid.UUID, *uuid.UUID, error) {
	brigadeID, err := parseUUID(brigadeIDValue, "brigade_id")
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, err
	}
	memberID, err := parseUUID(memberIDValue, "member_id")
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, err
	}
	changedBy, err := parseOptionalUUID(changedByValue, "changed_by_user_id")
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, err
	}
	return brigadeID, memberID, changedBy, nil
}

func parseBrigadeSkillIDs(brigadeIDValue string, skillIDValue string) (uuid.UUID, uuid.UUID, error) {
	brigadeID, err := parseUUID(brigadeIDValue, "brigade_id")
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	skillID, err := parseUUID(skillIDValue, "skill_id")
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return brigadeID, skillID, nil
}

func optionalString(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
}

func requestIDFromContext(ctx context.Context) *string {
	requestID, ok := pkg.RequestIDFromContext(ctx)
	if !ok {
		return nil
	}
	return &requestID
}

func traceIDFromContext(ctx context.Context) *string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}
	for _, key := range []string{"x-trace-id", "trace-id", "trace_id"} {
		if values := md.Get(key); len(values) > 0 && strings.TrimSpace(values[0]) != "" {
			value := strings.TrimSpace(values[0])
			return &value
		}
	}
	return nil
}

func actorFromContext(ctx context.Context) actorContext {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return actorContext{}
	}

	var actor actorContext
	if values := md.Get("x-actor-user-id"); len(values) > 0 && strings.TrimSpace(values[0]) != "" {
		if parsed, err := uuid.Parse(strings.TrimSpace(values[0])); err == nil {
			actor.UserID = &parsed
		}
	}

	if values := md.Get("x-actor-department-id"); len(values) > 0 && strings.TrimSpace(values[0]) != "" {
		if parsed, err := uuid.Parse(strings.TrimSpace(values[0])); err == nil {
			actor.DepartmentID = &parsed
		}
	}

	if values := md.Get("x-actor-roles"); len(values) > 0 {
		for _, value := range values {
			for _, role := range strings.Split(value, ",") {
				role = strings.TrimSpace(role)
				if role != "" {
					actor.Roles = append(actor.Roles, role)
				}
			}
		}
	}

	return actor
}

func fromProtoScheduleItems(items []*brigadev1.BrigadeScheduleItem) ([]*models.BrigadeScheduleItem, error) {
	result := make([]*models.BrigadeScheduleItem, 0, len(items))
	for _, item := range items {
		validFrom, err := parseDatePtr(item.ValidFrom, "valid_from")
		if err != nil {
			return nil, err
		}
		validTo, err := parseDatePtr(item.ValidTo, "valid_to")
		if err != nil {
			return nil, err
		}

		result = append(result, &models.BrigadeScheduleItem{
			DayOfWeek: int16(item.GetDayOfWeek()),
			StartsAt:  item.GetStartsAt(),
			EndsAt:    item.GetEndsAt(),
			Timezone:  item.GetTimezone(),
			ValidFrom: validFrom,
			ValidTo:   validTo,
		})
	}
	return result, nil
}

func parseDatePtr(value *string, field string) (*time.Time, error) {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil, nil
	}

	parsed, err := time.Parse(time.DateOnly, strings.TrimSpace(*value))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s: %v", models.ErrValidation, field, err)
	}
	return &parsed, nil
}

func toProtoBrigades(items []*models.Brigade) []*brigadev1.Brigade {
	result := make([]*brigadev1.Brigade, 0, len(items))
	for _, item := range items {
		result = append(result, ToProtoBrigade(item))
	}
	return result
}

func toProtoMembers(items []*models.BrigadeMember) []*brigadev1.BrigadeMember {
	result := make([]*brigadev1.BrigadeMember, 0, len(items))
	for _, item := range items {
		result = append(result, ToProtoBrigadeMember(item))
	}
	return result
}

func toProtoSchedule(items []*models.BrigadeSchedule) []*brigadev1.BrigadeSchedule {
	result := make([]*brigadev1.BrigadeSchedule, 0, len(items))
	for _, item := range items {
		result = append(result, ToProtoBrigadeSchedule(item))
	}
	return result
}

func toProtoZones(items []*models.BrigadeZone) []*brigadev1.BrigadeZone {
	result := make([]*brigadev1.BrigadeZone, 0, len(items))
	for _, item := range items {
		result = append(result, ToProtoBrigadeZone(item))
	}
	return result
}

func brigadeStatusError(method string, err error) error {
	return status.Errorf(brigadeErrorCode(err), "failed %s: %v", method, err)
}

func brigadeErrorCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}

	switch {
	case errors.Is(err, models.ErrValidation),
		errors.Is(err, models.ErrInvalidStatus),
		errors.Is(err, models.ErrInvalidRole),
		errors.Is(err, models.ErrInvalidAvailability),
		errors.Is(err, models.ErrInvalidGeometry):
		return codes.InvalidArgument
	case errors.Is(err, models.ErrNotFound):
		return codes.NotFound
	case errors.Is(err, models.ErrAlreadyExists),
		errors.Is(err, models.ErrIdempotencyConflict):
		return codes.AlreadyExists
	case errors.Is(err, models.ErrPermissionDenied):
		return codes.PermissionDenied
	case errors.Is(err, models.ErrIdempotencyInProgress):
		return codes.Aborted
	case errors.Is(err, models.ErrScheduleConflict),
		errors.Is(err, models.ErrBrigadeUnavailable),
		errors.Is(err, models.ErrBrigadeCannotHandle),
		errors.Is(err, models.ErrIdempotencyFailed):
		return codes.FailedPrecondition
	default:
		return codes.Internal
	}
}
