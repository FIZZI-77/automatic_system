package handler

import (
	"analytics/models"
	"analytics/src/core/service"
	"context"
	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"strings"
)

type Handler struct {
	analyticsv1.UnimplementedAnalyticsServiceServer
	s service.AnalyticsService
}

func New(s service.AnalyticsService) *Handler {
	return &Handler{s: s}
}

func (h *Handler) GetTicketOverview(c context.Context, q *analyticsv1.GetTicketOverviewRequest) (*analyticsv1.GetTicketOverviewResponse, error) {
	if e := auth(c); e != nil {
		return nil, e
	}
	v, e := h.s.Overview(c, filter(q.GetFilter()))
	if e != nil {
		return nil, internal(e)
	}
	return &analyticsv1.GetTicketOverviewResponse{
		Created:              v.Created,
		Completed:            v.Completed,
		Canceled:             v.Canceled,
		Active:               v.Active,
		CompletionRate:       v.CompletionRate,
		AvgResponseSeconds:   v.AvgResponseSeconds,
		AvgResolutionSeconds: v.AvgResolutionSeconds,
	}, nil
}
func (h *Handler) GetSLASummary(c context.Context, q *analyticsv1.GetSLASummaryRequest) (*analyticsv1.GetSLASummaryResponse, error) {
	if e := auth(c); e != nil {
		return nil, e
	}
	v, e := h.s.SLA(c, filter(q.GetFilter()))
	if e != nil {
		return nil, internal(e)
	}
	return &analyticsv1.GetSLASummaryResponse{
		ResponseWarnings:   v.ResponseWarnings,
		ResponseBreaches:   v.ResponseBreaches,
		ResolutionWarnings: v.ResolutionWarnings,
		ResolutionBreaches: v.ResolutionBreaches,
		Completed:          v.Completed,
		BreachRate:         v.BreachRate,
	}, nil
}
func (h *Handler) ListTicketBreakdown(c context.Context, q *analyticsv1.ListTicketBreakdownRequest) (*analyticsv1.ListTicketBreakdownResponse, error) {
	if e := auth(c); e != nil {
		return nil, e
	}
	d := strings.TrimPrefix(q.GetDimension().String(), "BREAKDOWN_DIMENSION_")
	items, total, e := h.s.Breakdown(c, filter(q.GetFilter()), d, q.GetLimit())
	if e != nil {
		return nil, status.Error(codes.InvalidArgument, e.Error())
	}
	out := make([]*analyticsv1.TicketBreakdown, 0, len(items))
	for _, v := range items {
		out = append(out, &analyticsv1.TicketBreakdown{
			Key:     v.Key,
			Count:   v.Count,
			Percent: v.Percent,
		})
	}
	return &analyticsv1.ListTicketBreakdownResponse{Items: out, Total: total}, nil
}
func (h *Handler) ListDailyTicketMetrics(c context.Context, q *analyticsv1.ListDailyTicketMetricsRequest) (*analyticsv1.ListDailyTicketMetricsResponse, error) {
	if e := auth(c); e != nil {
		return nil, e
	}
	items, e := h.s.Daily(c, filter(q.GetFilter()))
	if e != nil {
		return nil, internal(e)
	}
	out := make([]*analyticsv1.DailyTicketMetric, 0, len(items))
	for _, v := range items {
		out = append(out, &analyticsv1.DailyTicketMetric{
			Day:         timestamppb.New(v.Day),
			Created:     v.Created,
			Completed:   v.Completed,
			Canceled:    v.Canceled,
			SlaBreaches: v.SLABreaches,
		})
	}
	return &analyticsv1.ListDailyTicketMetricsResponse{Items: out}, nil
}
func filter(v *analyticsv1.AnalyticsFilter) models.Filter {
	if v == nil {
		return models.Filter{}
	}
	f := models.Filter{
		DepartmentID: v.DepartmentId,
		CategoryID:   v.CategoryId,
		Priority:     v.Priority,
	}
	if v.From != nil {
		x := v.From.AsTime()
		f.From = &x
	}
	if v.To != nil {
		x := v.To.AsTime()
		f.To = &x
	}
	return f
}
func auth(c context.Context) error {
	m, _ := metadata.FromIncomingContext(c)
	for _, r := range strings.Split(strings.Join(m.Get("x-actor-roles"), ","), ",") {
		if x := strings.ToLower(strings.TrimSpace(r)); x == "admin" || x == "dispatcher" {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "admin or dispatcher role required")
}
func internal(error) error {
	return status.Error(codes.Internal, "analytics query failed")
}

func (h *Handler) GetAssetSummary(c context.Context, q *analyticsv1.GetAssetSummaryRequest) (*analyticsv1.GetAssetSummaryResponse, error) {
	if e := auth(c); e != nil {
		return nil, e
	}
	v, e := h.s.AssetSummary(c, filter(q.Filter), q.AssetType, q.District)
	if e != nil {
		return nil, internal(e)
	}
	out := &analyticsv1.GetAssetSummaryResponse{
		AssetsCreated:       v.Created,
		Incidents:           v.Incidents,
		RepeatedIncidents:   v.Repeated,
		Repairs:             v.Repairs,
		Inspections:         v.Inspections,
		CriticalRiskUpdates: v.Critical,
	}
	for _, x := range v.ByType {
		out.ByType = append(out.ByType, assetBreakdown(x))
	}
	for _, x := range v.ByDistrict {
		out.ByDistrict = append(out.ByDistrict, assetBreakdown(x))
	}
	return out, nil
}

func assetBreakdown(value models.AssetBreakdown) *analyticsv1.AssetBreakdown {
	return &analyticsv1.AssetBreakdown{
		Key:                 value.Key,
		Incidents:           value.Incidents,
		RepeatedIncidents:   value.Repeated,
		Repairs:             value.Repairs,
		CriticalRiskUpdates: value.Critical,
	}
}
