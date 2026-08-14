package handlers

import (
	"gateway/models"
	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
	"net/http"
	"strings"
)

type AnalyticsHandler struct {
	client analyticsv1.AnalyticsServiceClient
}

func NewAnalyticsHandler(c analyticsv1.AnalyticsServiceClient) *AnalyticsHandler {
	return &AnalyticsHandler{client: c}
}
func (h *AnalyticsHandler) Overview(c *gin.Context) {
	var v models.AnalyticsRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.client.GetTicketOverview(dispatchContext(c), &analyticsv1.GetTicketOverviewRequest{Filter: analyticsFilter(v.Filter)})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AnalyticsHandler) SLA(c *gin.Context) {
	var v models.AnalyticsRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.client.GetSLASummary(dispatchContext(c), &analyticsv1.GetSLASummaryRequest{Filter: analyticsFilter(v.Filter)})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AnalyticsHandler) Breakdown(c *gin.Context) {
	var v models.AnalyticsBreakdownRequest
	if !bindJSON(c, &v) {
		return
	}
	d := analyticsv1.BreakdownDimension(analyticsv1.BreakdownDimension_value["BREAKDOWN_DIMENSION_"+strings.ToUpper(v.Dimension)])
	x, e := h.client.ListTicketBreakdown(dispatchContext(c), &analyticsv1.ListTicketBreakdownRequest{Filter: analyticsFilter(v.Filter), Dimension: d, Limit: v.Limit})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AnalyticsHandler) Daily(c *gin.Context) {
	var v models.AnalyticsRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.client.ListDailyTicketMetrics(dispatchContext(c), &analyticsv1.ListDailyTicketMetricsRequest{Filter: analyticsFilter(v.Filter)})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AnalyticsHandler) Assets(c *gin.Context) {
	var v models.AssetAnalyticsRequest
	if !bindJSON(c, &v) {
		return
	}
	ctx := metadata.AppendToOutgoingContext(dispatchContext(c), "x-actor-roles", strings.Join(actorRoles(c), ","))
	x, e := h.client.GetAssetSummary(ctx, &analyticsv1.GetAssetSummaryRequest{Filter: analyticsFilter(v.Filter), AssetType: v.AssetType, District: v.District})
	dispatchResponse(c, http.StatusOK, e, x)
}
func analyticsFilter(v *models.AnalyticsFilter) *analyticsv1.AnalyticsFilter {
	if v == nil {
		return nil
	}
	x := &analyticsv1.AnalyticsFilter{DepartmentId: v.DepartmentID, CategoryId: v.CategoryID, Priority: v.Priority}
	if v.From != nil {
		x.From = timestamppb.New(*v.From)
	}
	if v.To != nil {
		x.To = timestamppb.New(*v.To)
	}
	return x
}
