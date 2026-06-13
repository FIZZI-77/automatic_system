package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"gateway/models"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/metadata"
)

type BrigadeHandler struct {
	brigadeClient brigadev1.BrigadeServiceClient
}

func NewBrigadeHandler(brigadeClient brigadev1.BrigadeServiceClient) *BrigadeHandler {
	return &BrigadeHandler{brigadeClient: brigadeClient}
}

func (bh *BrigadeHandler) CreateBrigade(c *gin.Context) {
	var req models.CreateBrigadeRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.CreateBrigade(brigadeRequestContext(c), &brigadev1.CreateBrigadeRequest{
		DepartmentId:   req.DepartmentID,
		Name:           req.Name,
		Description:    req.Description,
		Specialization: stringOrEmpty(req.Specialization),
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusCreated, nil, &models.BrigadeResponse{Brigade: FromProtoBrigade(res.GetBrigade())})
}

func (bh *BrigadeHandler) GetBrigadeByID(c *gin.Context) {
	var req models.GetBrigadeByIDRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.GetBrigadeByID(brigadeRequestContext(c), &brigadev1.GetBrigadeByIDRequest{Id: req.ID})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeResponse{Brigade: FromProtoBrigade(res.GetBrigade())})
}

func (bh *BrigadeHandler) ListBrigades(c *gin.Context) {
	var req models.ListBrigadesRequest
	if !bindJSON(c, &req) {
		return
	}

	protoReq, ok := buildListBrigadesRequest(c, &req)
	if !ok {
		return
	}

	res, err := bh.brigadeClient.ListBrigades(brigadeRequestContext(c), protoReq)
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.ListBrigadesResponse{
		Brigades: FromProtoBrigades(res.GetBrigades()),
		Total:    res.GetTotal(),
	})
}

func (bh *BrigadeHandler) UpdateBrigade(c *gin.Context) {
	var req models.UpdateBrigadeRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.UpdateBrigade(brigadeRequestContext(c), &brigadev1.UpdateBrigadeRequest{
		Id:             req.ID,
		Name:           req.Name,
		Description:    req.Description,
		Specialization: req.Specialization,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeResponse{Brigade: FromProtoBrigade(res.GetBrigade())})
}

func (bh *BrigadeHandler) DeactivateBrigade(c *gin.Context) {
	var req models.BrigadeReasonRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.DeactivateBrigade(brigadeRequestContext(c), &brigadev1.DeactivateBrigadeRequest{
		Id:              req.ID,
		Reason:          req.Reason,
		ChangedByUserId: req.ChangedByUserID,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeResponse{Brigade: FromProtoBrigade(res.GetBrigade())})
}

func (bh *BrigadeHandler) ArchiveBrigade(c *gin.Context) {
	var req models.BrigadeReasonRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.ArchiveBrigade(brigadeRequestContext(c), &brigadev1.ArchiveBrigadeRequest{
		Id:              req.ID,
		Reason:          req.Reason,
		ChangedByUserId: req.ChangedByUserID,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeResponse{Brigade: FromProtoBrigade(res.GetBrigade())})
}

func (bh *BrigadeHandler) SetBrigadeStatus(c *gin.Context) {
	var req models.SetBrigadeStatusRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.SetBrigadeStatus(brigadeRequestContext(c), &brigadev1.SetBrigadeStatusRequest{
		BrigadeId:       req.BrigadeID,
		Status:          ToProtoBrigadeStatus(req.Status),
		Reason:          req.Reason,
		ChangedByUserId: req.ChangedByUserID,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeResponse{Brigade: FromProtoBrigade(res.GetBrigade())})
}

func (bh *BrigadeHandler) GetBrigadeStatusHistory(c *gin.Context) {
	var req models.BrigadePageRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.GetBrigadeStatusHistory(brigadeRequestContext(c), &brigadev1.GetBrigadeStatusHistoryRequest{
		BrigadeId: req.BrigadeID,
		Limit:     int32OrZero(req.Limit),
		Offset:    int32OrZero(req.Offset),
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeStatusHistoryResponse{
		History: FromProtoBrigadeStatusHistoryItems(res.GetHistory()),
		Total:   res.GetTotal(),
	})
}

func (bh *BrigadeHandler) AddBrigadeMember(c *gin.Context) {
	var req models.AddBrigadeMemberRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.AddBrigadeMember(brigadeRequestContext(c), &brigadev1.AddBrigadeMemberRequest{
		BrigadeId:       req.BrigadeID,
		UserId:          req.UserID,
		ProfileId:       req.ProfileID,
		Role:            ToProtoBrigadeMemberRole(req.Role),
		ChangedByUserId: req.ChangedByUserID,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusCreated, nil, &models.BrigadeMemberResponse{Member: FromProtoBrigadeMember(res.GetMember())})
}

func (bh *BrigadeHandler) RemoveBrigadeMember(c *gin.Context) {
	var req models.BrigadeMemberMutationRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.RemoveBrigadeMember(brigadeRequestContext(c), &brigadev1.RemoveBrigadeMemberRequest{
		BrigadeId:       req.BrigadeID,
		MemberId:        req.MemberID,
		Reason:          req.Reason,
		ChangedByUserId: req.ChangedByUserID,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeMemberResponse{Member: FromProtoBrigadeMember(res.GetMember())})
}

func (bh *BrigadeHandler) ChangeBrigadeMemberRole(c *gin.Context) {
	var req models.ChangeBrigadeMemberRoleRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.ChangeBrigadeMemberRole(brigadeRequestContext(c), &brigadev1.ChangeBrigadeMemberRoleRequest{
		BrigadeId:       req.BrigadeID,
		MemberId:        req.MemberID,
		Role:            ToProtoBrigadeMemberRole(req.Role),
		ChangedByUserId: req.ChangedByUserID,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeMemberResponse{Member: FromProtoBrigadeMember(res.GetMember())})
}

func (bh *BrigadeHandler) SetBrigadeMemberAvailability(c *gin.Context) {
	var req models.SetBrigadeMemberAvailabilityRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.SetBrigadeMemberAvailability(brigadeRequestContext(c), &brigadev1.SetBrigadeMemberAvailabilityRequest{
		BrigadeId:       req.BrigadeID,
		MemberId:        req.MemberID,
		Status:          ToProtoBrigadeMemberAvailability(req.Status),
		Reason:          req.Reason,
		ChangedByUserId: req.ChangedByUserID,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeMemberResponse{Member: FromProtoBrigadeMember(res.GetMember())})
}

func (bh *BrigadeHandler) ListBrigadeMembers(c *gin.Context) {
	var req models.ListBrigadeMembersRequest
	if !bindJSON(c, &req) {
		return
	}

	protoReq := &brigadev1.ListBrigadeMembersRequest{
		BrigadeId: req.BrigadeID,
		Active:    req.Active,
		Limit:     int32OrZero(req.Limit),
		Offset:    int32OrZero(req.Offset),
	}
	if req.Role != nil {
		role := ToProtoBrigadeMemberRole(*req.Role)
		protoReq.Role = &role
	}
	if req.AvailabilityStatus != nil {
		status := ToProtoBrigadeMemberAvailability(*req.AvailabilityStatus)
		protoReq.AvailabilityStatus = &status
	}

	res, err := bh.brigadeClient.ListBrigadeMembers(brigadeRequestContext(c), protoReq)
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.ListBrigadeMembersResponse{
		Members: FromProtoBrigadeMembers(res.GetMembers()),
		Total:   res.GetTotal(),
	})
}

func (bh *BrigadeHandler) GetBrigadeMemberHistory(c *gin.Context) {
	var req models.BrigadeMemberHistoryRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.GetBrigadeMemberHistory(brigadeRequestContext(c), &brigadev1.GetBrigadeMemberHistoryRequest{
		BrigadeId: req.BrigadeID,
		MemberId:  req.MemberID,
		Limit:     int32OrZero(req.Limit),
		Offset:    int32OrZero(req.Offset),
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeMemberHistoryResponse{
		History: FromProtoBrigadeMemberHistoryItems(res.GetHistory()),
		Total:   res.GetTotal(),
	})
}

func (bh *BrigadeHandler) GetBrigadeMemberStatusHistory(c *gin.Context) {
	var req models.BrigadeMemberHistoryRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.GetBrigadeMemberStatusHistory(brigadeRequestContext(c), &brigadev1.GetBrigadeMemberStatusHistoryRequest{
		BrigadeId: req.BrigadeID,
		MemberId:  req.MemberID,
		Limit:     int32OrZero(req.Limit),
		Offset:    int32OrZero(req.Offset),
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeMemberStatusHistoryResponse{
		History: FromProtoBrigadeMemberStatusHistoryItems(res.GetHistory()),
		Total:   res.GetTotal(),
	})
}

func (bh *BrigadeHandler) GetBrigadeByUserID(c *gin.Context) {
	var req models.GetBrigadeByUserIDRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.GetBrigadeByUserID(brigadeRequestContext(c), &brigadev1.GetBrigadeByUserIDRequest{
		UserId:     req.UserID,
		OnlyActive: req.OnlyActive,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.GetBrigadeByUserIDResponse{
		Brigade: FromProtoBrigade(res.GetBrigade()),
		Member:  FromProtoBrigadeMember(res.GetMember()),
	})
}

func (bh *BrigadeHandler) CreateSkill(c *gin.Context) {
	var req models.CreateSkillRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.CreateSkill(brigadeRequestContext(c), &brigadev1.CreateSkillRequest{
		Code:        req.Code,
		Name:        req.Name,
		Description: req.Description,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusCreated, nil, &models.SkillResponse{Skill: FromProtoSkill(res.GetSkill())})
}

func (bh *BrigadeHandler) UpdateSkill(c *gin.Context) {
	var req models.UpdateSkillRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.UpdateSkill(brigadeRequestContext(c), &brigadev1.UpdateSkillRequest{
		Id:          req.ID,
		Code:        req.Code,
		Name:        req.Name,
		Description: req.Description,
		Active:      req.Active,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.SkillResponse{Skill: FromProtoSkill(res.GetSkill())})
}

func (bh *BrigadeHandler) DeactivateSkill(c *gin.Context) {
	var req models.IDRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.DeactivateSkill(brigadeRequestContext(c), &brigadev1.DeactivateSkillRequest{Id: req.ID})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.SkillResponse{Skill: FromProtoSkill(res.GetSkill())})
}

func (bh *BrigadeHandler) ListSkills(c *gin.Context) {
	var req models.ListSkillsRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.ListSkills(brigadeRequestContext(c), &brigadev1.ListSkillsRequest{
		Active: req.Active,
		Query:  req.Query,
		Limit:  int32OrZero(req.Limit),
		Offset: int32OrZero(req.Offset),
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.ListSkillsResponse{
		Skills: FromProtoSkills(res.GetSkills()),
		Total:  res.GetTotal(),
	})
}

func (bh *BrigadeHandler) AddBrigadeSkill(c *gin.Context) {
	var req models.BrigadeSkillRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.AddBrigadeSkill(brigadeRequestContext(c), &brigadev1.AddBrigadeSkillRequest{
		BrigadeId: req.BrigadeID,
		SkillId:   req.SkillID,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusCreated, nil, &models.BrigadeSkillResponse{BrigadeSkill: FromProtoBrigadeSkill(res.GetBrigadeSkill())})
}

func (bh *BrigadeHandler) RemoveBrigadeSkill(c *gin.Context) {
	var req models.BrigadeSkillRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.RemoveBrigadeSkill(brigadeRequestContext(c), &brigadev1.RemoveBrigadeSkillRequest{
		BrigadeId: req.BrigadeID,
		SkillId:   req.SkillID,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeSkillResponse{BrigadeSkill: FromProtoBrigadeSkill(res.GetBrigadeSkill())})
}

func (bh *BrigadeHandler) ListBrigadeSkills(c *gin.Context) {
	var req models.ListBrigadeSkillsRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.ListBrigadeSkills(brigadeRequestContext(c), &brigadev1.ListBrigadeSkillsRequest{
		BrigadeId: req.BrigadeID,
		Active:    req.Active,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.ListBrigadeSkillsResponse{Skills: FromProtoBrigadeSkills(res.GetSkills())})
}

func (bh *BrigadeHandler) SetBrigadeSchedule(c *gin.Context) {
	var req models.SetBrigadeScheduleRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.SetBrigadeSchedule(brigadeRequestContext(c), &brigadev1.SetBrigadeScheduleRequest{
		BrigadeId: req.BrigadeID,
		Items:     ToProtoScheduleItems(req.Items),
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeScheduleResponse{Schedule: FromProtoBrigadeSchedules(res.GetSchedule())})
}

func (bh *BrigadeHandler) ListBrigadeSchedule(c *gin.Context) {
	var req models.ListBrigadeScheduleRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.ListBrigadeSchedule(brigadeRequestContext(c), &brigadev1.ListBrigadeScheduleRequest{
		BrigadeId: req.BrigadeID,
		Active:    req.Active,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeScheduleResponse{Schedule: FromProtoBrigadeSchedules(res.GetSchedule())})
}

func (bh *BrigadeHandler) CreateBrigadeZone(c *gin.Context) {
	var req models.CreateBrigadeZoneRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.CreateBrigadeZone(brigadeRequestContext(c), &brigadev1.CreateBrigadeZoneRequest{
		BrigadeId:    req.BrigadeID,
		DepartmentId: req.DepartmentID,
		Name:         req.Name,
		GeoJson:      req.GeoJSON,
		Priority:     req.Priority,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusCreated, nil, &models.BrigadeZoneResponse{Zone: FromProtoBrigadeZone(res.GetZone())})
}

func (bh *BrigadeHandler) UpdateBrigadeZone(c *gin.Context) {
	var req models.UpdateBrigadeZoneRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.UpdateBrigadeZone(brigadeRequestContext(c), &brigadev1.UpdateBrigadeZoneRequest{
		Id:       req.ID,
		Name:     req.Name,
		GeoJson:  req.GeoJSON,
		Priority: req.Priority,
		Active:   req.Active,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeZoneResponse{Zone: FromProtoBrigadeZone(res.GetZone())})
}

func (bh *BrigadeHandler) DeleteBrigadeZone(c *gin.Context) {
	var req models.IDRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.DeleteBrigadeZone(brigadeRequestContext(c), &brigadev1.DeleteBrigadeZoneRequest{Id: req.ID})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.BrigadeZoneResponse{Zone: FromProtoBrigadeZone(res.GetZone())})
}

func (bh *BrigadeHandler) ListBrigadeZones(c *gin.Context) {
	var req models.ListBrigadeZonesRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.ListBrigadeZones(brigadeRequestContext(c), &brigadev1.ListBrigadeZonesRequest{
		BrigadeId: req.BrigadeID,
		Active:    req.Active,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.ListBrigadeZonesResponse{Zones: FromProtoBrigadeZones(res.GetZones())})
}

func (bh *BrigadeHandler) CheckBrigadeCoversPoint(c *gin.Context) {
	var req models.CheckBrigadeCoversPointRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.CheckBrigadeCoversPoint(brigadeRequestContext(c), &brigadev1.CheckBrigadeCoversPointRequest{
		BrigadeId: req.BrigadeID,
		Longitude: req.Longitude,
		Latitude:  req.Latitude,
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.CheckBrigadeCoversPointResponse{
		Covers:       res.GetCovers(),
		MatchedZones: FromProtoBrigadeZones(res.GetMatchedZones()),
	})
}

func (bh *BrigadeHandler) FindBrigadesByPoint(c *gin.Context) {
	var req models.FindBrigadesByPointRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.FindBrigadesByPoint(brigadeRequestContext(c), &brigadev1.FindBrigadesByPointRequest{
		DepartmentId:     req.DepartmentID,
		Longitude:        req.Longitude,
		Latitude:         req.Latitude,
		OnlyAvailable:    req.OnlyAvailable,
		RequiredSkillIds: req.RequiredSkillIDs,
		RequiredRoles:    ToProtoBrigadeMemberRoles(req.RequiredRoles),
		Limit:            int32OrZero(req.Limit),
		Offset:           int32OrZero(req.Offset),
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.ListBrigadesResponse{
		Brigades: FromProtoBrigades(res.GetBrigades()),
		Total:    res.GetTotal(),
	})
}

func (bh *BrigadeHandler) GetAvailableBrigades(c *gin.Context) {
	var req models.GetAvailableBrigadesRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.GetAvailableBrigades(brigadeRequestContext(c), &brigadev1.GetAvailableBrigadesRequest{
		DepartmentId:     req.DepartmentID,
		Longitude:        req.Longitude,
		Latitude:         req.Latitude,
		RequiredSkillIds: req.RequiredSkillIDs,
		RequiredRoles:    ToProtoBrigadeMemberRoles(req.RequiredRoles),
		Limit:            int32OrZero(req.Limit),
		Offset:           int32OrZero(req.Offset),
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.ListBrigadesResponse{
		Brigades: FromProtoBrigades(res.GetBrigades()),
		Total:    res.GetTotal(),
	})
}

func (bh *BrigadeHandler) CheckBrigadeCanHandleTicket(c *gin.Context) {
	var req models.CheckBrigadeCanHandleTicketRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := bh.brigadeClient.CheckBrigadeCanHandleTicket(brigadeRequestContext(c), &brigadev1.CheckBrigadeCanHandleTicketRequest{
		BrigadeId:        req.BrigadeID,
		DepartmentId:     req.DepartmentID,
		Longitude:        req.Longitude,
		Latitude:         req.Latitude,
		RequiredSkillIds: req.RequiredSkillIDs,
		RequiredRoles:    ToProtoBrigadeMemberRoles(req.RequiredRoles),
	})
	if err != nil {
		brigadeResponse(c, http.StatusInternalServerError, err, nil)
		return
	}
	brigadeResponse(c, http.StatusOK, nil, &models.CheckBrigadeCanHandleTicketResponse{
		CanHandle: res.GetCanHandle(),
		Reasons:   res.GetReasons(),
	})
}

func buildListBrigadesRequest(c *gin.Context, req *models.ListBrigadesRequest) (*brigadev1.ListBrigadesRequest, bool) {
	protoReq := &brigadev1.ListBrigadesRequest{
		DepartmentId:   req.DepartmentID,
		Specialization: req.Specialization,
		Limit:          int32OrZero(req.Limit),
		Offset:         int32OrZero(req.Offset),
	}
	if req.Status != nil {
		status := ToProtoBrigadeStatus(*req.Status)
		protoReq.Status = &status
	}
	if req.SortBy != nil {
		sortBy := ToProtoBrigadeSortBy(*req.SortBy)
		protoReq.SortBy = &sortBy
	}
	if req.SortOrder != nil {
		sortOrder := ToProtoBrigadeSortOrder(*req.SortOrder)
		protoReq.SortOrder = &sortOrder
	}
	if req.CreatedFrom != nil {
		createdFrom, err := ToProtoTimestamp(*req.CreatedFrom)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid created_from"})
			return nil, false
		}
		protoReq.CreatedFrom = createdFrom
	}
	if req.CreatedTo != nil {
		createdTo, err := ToProtoTimestamp(*req.CreatedTo)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid created_to"})
			return nil, false
		}
		protoReq.CreatedTo = createdTo
	}

	return protoReq, true
}

func brigadeRequestContext(c *gin.Context) context.Context {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	c.Set("brigade_cancel", cancel)
	return gatewayActorContext(ctx, c)
}

func brigadeResponse(c *gin.Context, httpStatus int, err error, response any) {
	if cancelValue, ok := c.Get("brigade_cancel"); ok {
		if cancel, ok := cancelValue.(context.CancelFunc); ok {
			defer cancel()
		}
	}
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	c.JSON(httpStatus, response)
}

func gatewayActorContext(ctx context.Context, c *gin.Context) context.Context {
	roles, _ := c.Get("roles")
	roleValues, _ := roles.([]string)

	values := []string{
		"x-actor-user-id", c.GetString("user_id"),
		"x-actor-roles", strings.Join(roleValues, ","),
	}
	if departmentID := strings.TrimSpace(c.GetHeader("X-Actor-Department-ID")); departmentID != "" {
		values = append(values, "x-actor-department-id", departmentID)
	}

	return metadata.AppendToOutgoingContext(ctx, values...)
}
