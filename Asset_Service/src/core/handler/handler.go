package handler

import (
	"asset/models"
	"asset/src/core/repository"
	"asset/src/core/service"
	"context"
	"errors"
	assetv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/asset/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"strings"
	"time"
)

type Handler struct {
	assetv1.UnimplementedAssetServiceServer
	s service.AssetService
}

func New(s service.AssetService) *Handler {
	return &Handler{s: s}
}

func (h *Handler) CreateAsset(c context.Context, q *assetv1.CreateAssetRequest) (*assetv1.AssetResponse, error) {
	d, a, e := ids(q.DepartmentId, q.ActorUserId)
	if e != nil {
		return nil, bad(e)
	}
	v := models.CreateInput{
		Asset: models.Asset{
			DepartmentID:           d,
			ExternalID:             q.ExternalId,
			Type:                   q.Type,
			Name:                   q.Name,
			Address:                q.Address,
			District:               q.District,
			Municipality:           q.Municipality,
			Geometry:               q.GeometryGeoJson,
			Model:                  q.Model,
			SerialNumber:           q.SerialNumber,
			InstallationYear:       q.InstallationYear,
			ServiceLifeYears:       q.ServiceLifeYears,
			Owner:                  q.Owner,
			ServiceOrganization:    q.ServiceOrganization,
			Contractor:             q.Contractor,
			InspectionIntervalDays: q.InspectionIntervalDays,
			ResponseNormMinutes:    q.ResponseNormMinutes,
			RepairNormMinutes:      q.RepairNormMinutes,
			Criticality:            q.Criticality,
		},
		ActorID: a,
	}
	if q.WarrantyUntil != nil {
		x := q.WarrantyUntil.AsTime()
		v.WarrantyUntil = &x
	}
	x, e := h.s.Create(c, v, priv(q.ActorRoles))
	return &assetv1.AssetResponse{Asset: pa(x)}, mapErr(e)
}
func (h *Handler) GetAsset(c context.Context, q *assetv1.GetAssetRequest) (*assetv1.AssetResponse, error) {
	id, e := uuid.Parse(q.AssetId)
	if e != nil {
		return nil, bad(e)
	}
	x, e := h.s.Get(c, id)
	return &assetv1.AssetResponse{Asset: pa(x)}, mapErr(e)
}
func (h *Handler) UpdateAsset(c context.Context, q *assetv1.UpdateAssetRequest) (*assetv1.AssetResponse, error) {
	id, e := uuid.Parse(q.AssetId)
	if e != nil {
		return nil, bad(e)
	}
	input := models.UpdateInput{
		ID:          id,
		Name:        q.Name,
		Address:     q.Address,
		Geometry:    q.GeometryGeoJson,
		Contractor:  q.Contractor,
		Criticality: q.Criticality,
	}
	x, e := h.s.Update(c, input, priv(q.ActorRoles))
	return &assetv1.AssetResponse{Asset: pa(x)}, mapErr(e)
}
func (h *Handler) ListAssets(c context.Context, q *assetv1.ListAssetsRequest) (*assetv1.ListAssetsResponse, error) {
	f := models.Filter{Type: q.Type, District: q.District, Limit: q.Limit, Offset: q.Offset}
	if q.DepartmentId != nil {
		id, e := uuid.Parse(*q.DepartmentId)
		if e != nil {
			return nil, bad(e)
		}
		f.DepartmentID = &id
	}
	if q.Status != nil {
		x := statusModel(*q.Status)
		f.Status = &x
	}
	if q.RiskLevel != nil {
		x := riskModel(*q.RiskLevel)
		f.RiskLevel = &x
	}
	xs, n, e := h.s.List(c, f)
	out := []*assetv1.Asset{}
	for _, x := range xs {
		out = append(out, pa(x))
	}
	return &assetv1.ListAssetsResponse{Assets: out, Total: n}, mapErr(e)
}
func (h *Handler) ChangeAssetStatus(c context.Context, q *assetv1.ChangeAssetStatusRequest) (*assetv1.AssetResponse, error) {
	id, a, e := ids(q.AssetId, q.ActorUserId)
	if e != nil {
		return nil, bad(e)
	}
	x, e := h.s.ChangeStatus(c, id, statusModel(q.Status), a, q.Reason, priv(q.ActorRoles))
	return &assetv1.AssetResponse{Asset: pa(x)}, mapErr(e)
}
func (h *Handler) FindNearbyAssets(c context.Context, q *assetv1.FindNearbyAssetsRequest) (*assetv1.ListAssetsResponse, error) {
	xs, e := h.s.Nearby(c, q.Latitude, q.Longitude, q.RadiusMeters, q.Type, q.Limit)
	out := []*assetv1.Asset{}
	for _, x := range xs {
		out = append(out, pa(x))
	}
	return &assetv1.ListAssetsResponse{Assets: out, Total: int64(len(out))}, mapErr(e)
}
func (h *Handler) RecordIncident(c context.Context, q *assetv1.RecordIncidentRequest) (*assetv1.IncidentResponse, error) {
	id, e := uuid.Parse(q.AssetId)
	if e != nil {
		return nil, bad(e)
	}
	v := models.Incident{
		AssetID:     id,
		TicketID:    optID(q.TicketId),
		FailureType: q.FailureType,
		Description: q.Description,
		Source:      q.Source,
		Priority:    q.Priority,
		OccurredAt:  pt(q.OccurredAt),
	}
	x, p, e := h.s.Incident(c, v, priv(q.ActorRoles))
	return &assetv1.IncidentResponse{Incident: pi(x), Prediction: pp(p)}, mapErr(e)
}
func (h *Handler) CompleteRepair(c context.Context, q *assetv1.CompleteRepairRequest) (*assetv1.RepairResponse, error) {
	id, e := uuid.Parse(q.AssetId)
	if e != nil {
		return nil, bad(e)
	}
	v := models.Repair{
		AssetID:            id,
		IncidentID:         optID(q.IncidentId),
		TicketID:           optID(q.TicketId),
		BrigadeID:          optID(q.BrigadeId),
		Description:        q.Description,
		ReplacedComponents: q.ReplacedComponents,
		DurationMinutes:    q.DurationMinutes,
		CompletedAt:        pt(q.CompletedAt),
	}
	x, p, e := h.s.Repair(c, v, priv(q.ActorRoles))
	return &assetv1.RepairResponse{Repair: pr(x), Prediction: pp(p)}, mapErr(e)
}
func (h *Handler) RecordInspection(c context.Context, q *assetv1.RecordInspectionRequest) (*assetv1.InspectionResponse, error) {
	id, a, e := ids(q.AssetId, q.InspectorUserId)
	if e != nil {
		return nil, bad(e)
	}
	inspection := models.Inspection{
		AssetID:        id,
		InspectorID:    a,
		Kind:           q.Kind,
		Result:         q.Result,
		DefectFound:    q.DefectFound,
		ConditionScore: q.ConditionScore,
		Recommendation: q.Recommendation,
		InspectedAt:    pt(q.InspectedAt),
	}
	x, p, e := h.s.Inspection(c, inspection, priv(q.ActorRoles))
	return &assetv1.InspectionResponse{Inspection: pin(x), Prediction: pp(p)}, mapErr(e)
}
func (h *Handler) CreateMaintenancePlan(c context.Context, q *assetv1.CreateMaintenancePlanRequest) (*assetv1.MaintenancePlanResponse, error) {
	id, e := uuid.Parse(q.AssetId)
	if e != nil {
		return nil, bad(e)
	}
	plan := models.Plan{
		AssetID:      id,
		Kind:         q.Kind,
		IntervalDays: q.IntervalDays,
		NextDueAt:    pt(q.NextDueAt),
	}
	x, e := h.s.CreatePlan(c, plan, priv(q.ActorRoles))
	return &assetv1.MaintenancePlanResponse{Plan: pplan(x)}, mapErr(e)
}
func (h *Handler) ListDueMaintenance(c context.Context, q *assetv1.ListDueMaintenanceRequest) (*assetv1.ListMaintenancePlansResponse, error) {
	var d *uuid.UUID
	if q.DepartmentId != nil {
		x, e := uuid.Parse(*q.DepartmentId)
		if e != nil {
			return nil, bad(e)
		}
		d = &x
	}
	xs, n, e := h.s.Due(c, d, pt(q.DueBefore), q.Limit, q.Offset)
	out := []*assetv1.MaintenancePlan{}
	for _, x := range xs {
		out = append(out, pplan(x))
	}
	return &assetv1.ListMaintenancePlansResponse{Plans: out, Total: n}, mapErr(e)
}
func (h *Handler) GetFailurePrediction(c context.Context, q *assetv1.GetFailurePredictionRequest) (*assetv1.FailurePredictionResponse, error) {
	id, e := uuid.Parse(q.AssetId)
	if e != nil {
		return nil, bad(e)
	}
	x, e := h.s.Prediction(c, id)
	return &assetv1.FailurePredictionResponse{Prediction: pp(x)}, mapErr(e)
}
func (h *Handler) RecalculateRisks(c context.Context, q *assetv1.RecalculateRisksRequest) (*assetv1.RecalculateRisksResponse, error) {
	var d *uuid.UUID
	if q.DepartmentId != nil {
		x, e := uuid.Parse(*q.DepartmentId)
		if e != nil {
			return nil, bad(e)
		}
		d = &x
	}
	n, e := h.s.Recalculate(c, d, priv(q.ActorRoles))
	return &assetv1.RecalculateRisksResponse{Updated: n}, mapErr(e)
}
func priv(r []string) bool {
	for _, x := range r {
		if x == "admin" || x == "dispatcher" || x == "worker" {
			return true
		}
	}
	return false
}
func ids(a, b string) (uuid.UUID, uuid.UUID, error) {
	x, e := uuid.Parse(a)
	if e != nil {
		return x, x, e
	}
	y, e := uuid.Parse(b)
	return x, y, e
}
func optID(v *string) *uuid.UUID {
	if v == nil {
		return nil
	}
	x, e := uuid.Parse(*v)
	if e != nil {
		return nil
	}
	return &x
}
func pt(v *timestamppb.Timestamp) time.Time {
	if v == nil {
		return time.Now().UTC()
	}
	return v.AsTime()
}
func bad(e error) error {
	return status.Error(codes.InvalidArgument, e.Error())
}

func mapErr(e error) error {
	if e == nil {
		return nil
	}
	if repository.IsNotFound(e) {
		return status.Error(codes.NotFound, "asset not found")
	}
	if errors.Is(e, models.ErrForbidden) {
		return status.Error(codes.PermissionDenied, e.Error())
	}
	return status.Error(codes.InvalidArgument, e.Error())
}
func statusModel(v assetv1.AssetStatus) models.Status {
	return models.Status(strings.TrimPrefix(v.String(), "ASSET_STATUS_"))
}
func riskModel(v assetv1.RiskLevel) models.RiskLevel {
	return models.RiskLevel(strings.TrimPrefix(v.String(), "RISK_LEVEL_"))
}
func pa(x *models.Asset) *assetv1.Asset {
	if x == nil {
		return nil
	}
	p := &assetv1.Asset{
		Id:                     x.ID.String(),
		ExternalId:             x.ExternalID,
		DepartmentId:           x.DepartmentID.String(),
		Type:                   x.Type,
		Name:                   x.Name,
		Address:                x.Address,
		District:               x.District,
		Municipality:           x.Municipality,
		GeometryGeoJson:        x.Geometry,
		Status:                 assetv1.AssetStatus(assetv1.AssetStatus_value["ASSET_STATUS_"+string(x.Status)]),
		Model:                  x.Model,
		SerialNumber:           x.SerialNumber,
		InstallationYear:       x.InstallationYear,
		ServiceLifeYears:       x.ServiceLifeYears,
		Owner:                  x.Owner,
		ServiceOrganization:    x.ServiceOrganization,
		Contractor:             x.Contractor,
		InspectionIntervalDays: x.InspectionIntervalDays,
		ResponseNormMinutes:    x.ResponseNormMinutes,
		RepairNormMinutes:      x.RepairNormMinutes,
		Criticality:            x.Criticality,
		RiskScore:              x.RiskScore,
		RiskLevel:              assetv1.RiskLevel(assetv1.RiskLevel_value["RISK_LEVEL_"+string(x.RiskLevel)]),
		CreatedAt:              timestamppb.New(x.CreatedAt),
		UpdatedAt:              timestamppb.New(x.UpdatedAt),
	}
	if x.WarrantyUntil != nil {
		p.WarrantyUntil = timestamppb.New(*x.WarrantyUntil)
	}
	if x.LastRepairAt != nil {
		p.LastRepairAt = timestamppb.New(*x.LastRepairAt)
	}
	if x.NextInspectionAt != nil {
		p.NextInspectionAt = timestamppb.New(*x.NextInspectionAt)
	}
	return p
}
func pp(x *models.Prediction) *assetv1.FailurePrediction {
	if x == nil {
		return nil
	}
	return &assetv1.FailurePrediction{
		AssetId:                x.AssetID.String(),
		RiskScore:              x.Score,
		RiskLevel:              assetv1.RiskLevel(assetv1.RiskLevel_value["RISK_LEVEL_"+string(x.Level)]),
		FailureProbability_90D: x.Probability,
		Factors:                x.Factors,
		RecommendedAction:      x.Action,
		CalculatedAt:           timestamppb.New(x.CalculatedAt),
	}
}
func pi(x *models.Incident) *assetv1.Incident {
	if x == nil {
		return nil
	}
	return &assetv1.Incident{
		Id:          x.ID.String(),
		AssetId:     x.AssetID.String(),
		FailureType: x.FailureType,
		Description: x.Description,
		Source:      x.Source,
		Priority:    x.Priority,
		Repeated:    x.Repeated,
		OccurredAt:  timestamppb.New(x.OccurredAt),
	}
}
func pr(x *models.Repair) *assetv1.Repair {
	if x == nil {
		return nil
	}
	return &assetv1.Repair{
		Id:                 x.ID.String(),
		AssetId:            x.AssetID.String(),
		Description:        x.Description,
		ReplacedComponents: x.ReplacedComponents,
		DurationMinutes:    x.DurationMinutes,
		CompletedAt:        timestamppb.New(x.CompletedAt),
	}
}
func pin(x *models.Inspection) *assetv1.Inspection {
	if x == nil {
		return nil
	}
	return &assetv1.Inspection{
		Id:              x.ID.String(),
		AssetId:         x.AssetID.String(),
		InspectorUserId: x.InspectorID.String(),
		Kind:            x.Kind,
		Result:          x.Result,
		DefectFound:     x.DefectFound,
		ConditionScore:  x.ConditionScore,
		Recommendation:  x.Recommendation,
		InspectedAt:     timestamppb.New(x.InspectedAt),
	}
}
func pplan(x *models.Plan) *assetv1.MaintenancePlan {
	if x == nil {
		return nil
	}
	return &assetv1.MaintenancePlan{
		Id:           x.ID.String(),
		AssetId:      x.AssetID.String(),
		Kind:         x.Kind,
		IntervalDays: x.IntervalDays,
		NextDueAt:    timestamppb.New(x.NextDueAt),
		Active:       x.Active,
	}
}
