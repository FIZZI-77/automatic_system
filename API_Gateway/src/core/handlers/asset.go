package handlers

import (
	"gateway/models"
	assetv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/asset/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/types/known/timestamppb"
	"net/http"
	"strings"
	"time"
)

type AssetHandler struct{ c assetv1.AssetServiceClient }

func NewAssetHandler(c assetv1.AssetServiceClient) *AssetHandler { return &AssetHandler{c} }
func (h *AssetHandler) Create(c *gin.Context) {
	var v models.CreateAssetRequest
	if !bindJSON(c, &v) {
		return
	}
	u, r := principal(c)
	q := &assetv1.CreateAssetRequest{ActorUserId: u, ActorRoles: r, ExternalId: v.ExternalID, DepartmentId: v.DepartmentID, Type: v.Type, Name: v.Name, Address: v.Address, District: v.District, Municipality: v.Municipality, GeometryGeoJson: v.GeometryGeoJSON, Model: v.Model, SerialNumber: v.SerialNumber, InstallationYear: v.InstallationYear, ServiceLifeYears: v.ServiceLifeYears, Owner: v.Owner, ServiceOrganization: v.ServiceOrganization, Contractor: v.Contractor, InspectionIntervalDays: v.InspectionIntervalDays, ResponseNormMinutes: v.ResponseNormMinutes, RepairNormMinutes: v.RepairNormMinutes, Criticality: v.Criticality}
	x, e := h.c.CreateAsset(dispatchContext(c), q)
	dispatchResponse(c, http.StatusCreated, e, x)
}
func (h *AssetHandler) Get(c *gin.Context) {
	var v models.AssetIDRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.c.GetAsset(dispatchContext(c), &assetv1.GetAssetRequest{AssetId: v.AssetID})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AssetHandler) Update(c *gin.Context) {
	var v models.UpdateAssetRequest
	if !bindJSON(c, &v) {
		return
	}
	u, r := principal(c)
	x, e := h.c.UpdateAsset(dispatchContext(c), &assetv1.UpdateAssetRequest{AssetId: v.AssetID, ActorUserId: u, ActorRoles: r, Name: v.Name, Address: v.Address, GeometryGeoJson: v.GeometryGeoJSON, Contractor: v.Contractor, Criticality: v.Criticality})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AssetHandler) ChangeStatus(c *gin.Context) {
	var v models.ChangeAssetStatusRequest
	if !bindJSON(c, &v) {
		return
	}
	u, r := principal(c)
	st := assetv1.AssetStatus(assetv1.AssetStatus_value["ASSET_STATUS_"+strings.ToUpper(v.Status)])
	x, e := h.c.ChangeAssetStatus(dispatchContext(c), &assetv1.ChangeAssetStatusRequest{AssetId: v.AssetID, Status: st, ActorUserId: u, ActorRoles: r, Reason: v.Reason})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AssetHandler) List(c *gin.Context) {
	var v models.ListAssetsRequest
	if !bindJSON(c, &v) {
		return
	}
	q := &assetv1.ListAssetsRequest{DepartmentId: v.DepartmentID, Type: v.Type, District: v.District, Limit: v.Limit, Offset: v.Offset}
	if v.Status != nil {
		x := assetv1.AssetStatus(assetv1.AssetStatus_value["ASSET_STATUS_"+strings.ToUpper(*v.Status)])
		q.Status = &x
	}
	if v.RiskLevel != nil {
		x := assetv1.RiskLevel(assetv1.RiskLevel_value["RISK_LEVEL_"+strings.ToUpper(*v.RiskLevel)])
		q.RiskLevel = &x
	}
	x, e := h.c.ListAssets(dispatchContext(c), q)
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AssetHandler) Nearby(c *gin.Context) {
	var v models.NearbyAssetsRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.c.FindNearbyAssets(dispatchContext(c), &assetv1.FindNearbyAssetsRequest{Latitude: v.Latitude, Longitude: v.Longitude, RadiusMeters: v.RadiusMeters, Type: v.Type, Limit: v.Limit})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AssetHandler) Incident(c *gin.Context) {
	var v models.AssetIncidentRequest
	if !bindJSON(c, &v) {
		return
	}
	u, r := principal(c)
	x, e := h.c.RecordIncident(dispatchContext(c), &assetv1.RecordIncidentRequest{AssetId: v.AssetID, TicketId: v.TicketID, FailureType: v.FailureType, Description: v.Description, Source: v.Source, Priority: v.Priority, OccurredAt: ts(v.OccurredAt), ActorUserId: u, ActorRoles: r})
	dispatchResponse(c, http.StatusCreated, e, x)
}
func (h *AssetHandler) Repair(c *gin.Context) {
	var v models.AssetRepairRequest
	if !bindJSON(c, &v) {
		return
	}
	u, r := principal(c)
	x, e := h.c.CompleteRepair(dispatchContext(c), &assetv1.CompleteRepairRequest{AssetId: v.AssetID, IncidentId: v.IncidentID, TicketId: v.TicketID, BrigadeId: v.BrigadeID, Description: v.Description, ReplacedComponents: v.ReplacedComponents, DurationMinutes: v.DurationMinutes, CompletedAt: ts(v.CompletedAt), ActorUserId: u, ActorRoles: r})
	dispatchResponse(c, http.StatusCreated, e, x)
}
func (h *AssetHandler) Inspection(c *gin.Context) {
	var v models.AssetInspectionRequest
	if !bindJSON(c, &v) {
		return
	}
	u, r := principal(c)
	x, e := h.c.RecordInspection(dispatchContext(c), &assetv1.RecordInspectionRequest{AssetId: v.AssetID, InspectorUserId: u, Kind: v.Kind, Result: v.Result, DefectFound: v.DefectFound, ConditionScore: v.ConditionScore, Recommendation: v.Recommendation, InspectedAt: ts(v.InspectedAt), ActorRoles: r})
	dispatchResponse(c, http.StatusCreated, e, x)
}
func (h *AssetHandler) Prediction(c *gin.Context) {
	var v models.AssetIDRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.c.GetFailurePrediction(dispatchContext(c), &assetv1.GetFailurePredictionRequest{AssetId: v.AssetID})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AssetHandler) CreatePlan(c *gin.Context) {
	var v models.MaintenancePlanRequest
	if !bindJSON(c, &v) {
		return
	}
	u, r := principal(c)
	x, e := h.c.CreateMaintenancePlan(dispatchContext(c), &assetv1.CreateMaintenancePlanRequest{AssetId: v.AssetID, Kind: v.Kind, IntervalDays: v.IntervalDays, NextDueAt: timestamppb.New(v.NextDueAt), ActorUserId: u, ActorRoles: r})
	dispatchResponse(c, http.StatusCreated, e, x)
}
func (h *AssetHandler) DuePlans(c *gin.Context) {
	var v models.DueMaintenanceRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.c.ListDueMaintenance(dispatchContext(c), &assetv1.ListDueMaintenanceRequest{DepartmentId: v.DepartmentID, DueBefore: timestamppb.New(v.DueBefore), Limit: v.Limit, Offset: v.Offset})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AssetHandler) Recalculate(c *gin.Context) {
	var v models.RecalculateAssetRisksRequest
	if !bindJSON(c, &v) {
		return
	}
	_, r := principal(c)
	x, e := h.c.RecalculateRisks(dispatchContext(c), &assetv1.RecalculateRisksRequest{DepartmentId: v.DepartmentID, ActorRoles: r})
	dispatchResponse(c, http.StatusOK, e, x)
}
func ts(v *time.Time) *timestamppb.Timestamp {
	if v == nil {
		return timestamppb.Now()
	}
	return timestamppb.New(*v)
}
