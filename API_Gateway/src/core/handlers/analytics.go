package handlers

import (
	"context"
	"gateway/models"
	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	"github.com/gin-gonic/gin"
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
	x, e := h.client.GetTicketOverview(analyticsContext(c), &analyticsv1.GetTicketOverviewRequest{Filter: analyticsFilter(v.Filter)})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AnalyticsHandler) SLA(c *gin.Context) {
	var v models.AnalyticsRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.client.GetSLASummary(analyticsContext(c), &analyticsv1.GetSLASummaryRequest{Filter: analyticsFilter(v.Filter)})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AnalyticsHandler) Breakdown(c *gin.Context) {
	var v models.AnalyticsBreakdownRequest
	if !bindJSON(c, &v) {
		return
	}
	d := analyticsv1.BreakdownDimension(analyticsv1.BreakdownDimension_value["BREAKDOWN_DIMENSION_"+strings.ToUpper(v.Dimension)])
	x, e := h.client.ListTicketBreakdown(analyticsContext(c), &analyticsv1.ListTicketBreakdownRequest{Filter: analyticsFilter(v.Filter), Dimension: d, Limit: v.Limit})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AnalyticsHandler) Daily(c *gin.Context) {
	var v models.AnalyticsRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.client.ListDailyTicketMetrics(analyticsContext(c), &analyticsv1.ListDailyTicketMetricsRequest{Filter: analyticsFilter(v.Filter)})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AnalyticsHandler) Assets(c *gin.Context) {
	var v models.AssetAnalyticsRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.client.GetAssetSummary(analyticsContext(c), &analyticsv1.GetAssetSummaryRequest{Filter: analyticsFilter(v.Filter), AssetType: v.AssetType, District: v.District})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *AnalyticsHandler) OperationalLatency(c *gin.Context) {
	var request models.OperationalLatencyRequest
	if !bindJSON(c, &request) {
		return
	}
	response, err := h.client.GetOperationalLatency(
		analyticsContext(c),
		&analyticsv1.GetOperationalLatencyRequest{
			Filter:  analyticsFilter(request.Filter),
			GroupBy: operationalLatencyDimension(request.GroupBy),
		},
	)
	dispatchResponse(c, http.StatusOK, err, response)
}
func (h *AnalyticsHandler) DispatchFailures(c *gin.Context) {
	var request models.AnalyticsRequest
	if !bindJSON(c, &request) {
		return
	}
	response, err := h.client.GetDispatchFailureSummary(analyticsContext(c), &analyticsv1.GetDispatchFailureSummaryRequest{Filter: analyticsFilter(request.Filter)})
	dispatchResponse(c, http.StatusOK, err, response)
}
func (h *AnalyticsHandler) BrigadeWorkload(c *gin.Context) {
	var request models.AnalyticsRequest
	if !bindJSON(c, &request) {
		return
	}
	response, err := h.client.GetBrigadeWorkload(analyticsContext(c), &analyticsv1.GetBrigadeWorkloadRequest{Filter: analyticsFilter(request.Filter)})
	dispatchResponse(c, http.StatusOK, err, response)
}
func (h *AnalyticsHandler) ActiveWorkers(c *gin.Context) {
	var request models.AnalyticsRequest
	if !bindJSON(c, &request) {
		return
	}
	response, err := h.client.GetActiveWorkers(analyticsContext(c), &analyticsv1.GetActiveWorkersRequest{Filter: analyticsFilter(request.Filter)})
	dispatchResponse(c, http.StatusOK, err, response)
}
func (h *AnalyticsHandler) AssignmentFunnel(c *gin.Context) {
	var request models.AnalyticsRequest
	if !bindJSON(c, &request) {
		return
	}
	response, err := h.client.GetAssignmentFunnel(analyticsContext(c), &analyticsv1.GetAssignmentFunnelRequest{Filter: analyticsFilter(request.Filter)})
	dispatchResponse(c, http.StatusOK, err, response)
}

func (h *AnalyticsHandler) DispatchEffectiveness(c *gin.Context) {
	var request models.AnalyticsRequest
	if !bindJSON(c, &request) {
		return
	}
	response, err := h.client.GetDispatchEffectiveness(
		analyticsContext(c),
		&analyticsv1.GetDispatchEffectivenessRequest{Filter: analyticsFilter(request.Filter)},
	)
	dispatchResponse(c, http.StatusOK, err, response)
}

func (h *AnalyticsHandler) OperationalInsights(c *gin.Context) {
	var request models.AnalyticsRequest
	if !bindJSON(c, &request) {
		return
	}
	response, err := h.client.GetOperationalInsights(
		analyticsContext(c),
		&analyticsv1.GetOperationalInsightsRequest{Filter: analyticsFilter(request.Filter)},
	)
	dispatchResponse(c, http.StatusOK, err, response)
}

func (h *AnalyticsHandler) ProjectionHealth(c *gin.Context) {
	response, err := h.client.GetProjectionHealth(analyticsContext(c), &analyticsv1.GetProjectionHealthRequest{})
	dispatchResponse(c, http.StatusOK, err, response)
}

func (h *AnalyticsHandler) DispatchOperations(c *gin.Context) {
	var request models.AnalyticsRequest
	if !bindJSON(c, &request) {
		return
	}
	response, err := h.client.ListDispatchOperations(
		analyticsContext(c),
		&analyticsv1.ListDispatchOperationsRequest{Filter: analyticsFilter(request.Filter), Limit: 25},
	)
	dispatchResponse(c, http.StatusOK, err, response)
}

func (h *AnalyticsHandler) BrigadePerformance(c *gin.Context) {
	var request models.AnalyticsRequest
	if !bindJSON(c, &request) {
		return
	}
	response, err := h.client.GetBrigadePerformance(
		analyticsContext(c),
		&analyticsv1.GetBrigadePerformanceRequest{Filter: analyticsFilter(request.Filter)},
	)
	dispatchResponse(c, http.StatusOK, err, response)
}

func analyticsContext(c *gin.Context) context.Context {
	return dispatchContext(c)
}

func operationalLatencyDimension(value string) analyticsv1.OperationalLatencyDimension {
	key := "OPERATIONAL_LATENCY_DIMENSION_" + strings.ToUpper(strings.TrimSpace(value))
	return analyticsv1.OperationalLatencyDimension(analyticsv1.OperationalLatencyDimension_value[key])
}
func analyticsFilter(v *models.AnalyticsFilter) *analyticsv1.AnalyticsFilter {
	if v == nil {
		return nil
	}
	x := &analyticsv1.AnalyticsFilter{
		DepartmentId:   v.DepartmentID,
		CategoryId:     v.CategoryID,
		Priority:       v.Priority,
		BrigadeId:      v.BrigadeID,
		AssignmentMode: v.AssignmentMode,
		FailureCode:    v.FailureCode,
		Success:        v.Success,
	}
	if v.From != nil {
		x.From = timestamppb.New(*v.From)
	}
	if v.To != nil {
		x.To = timestamppb.New(*v.To)
	}
	return x
}
