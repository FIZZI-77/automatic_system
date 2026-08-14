package handlers

import (
	"gateway/models"
	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	reportv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/report/v1"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type ReportHandler struct{ client reportv1.ReportServiceClient }

func NewReportHandler(c reportv1.ReportServiceClient) *ReportHandler {
	return &ReportHandler{client: c}
}
func (h *ReportHandler) Create(c *gin.Context) {
	var v models.CreateReportRequest
	if !bindJSON(c, &v) {
		return
	}
	u, r := principal(c)
	x, e := h.client.CreateReport(dispatchContext(c), &reportv1.CreateReportRequest{RequestedBy: u, ActorRoles: r, Name: v.Name, Type: reportv1.ReportType(reportv1.ReportType_value["REPORT_TYPE_"+strings.ToUpper(v.Type)]), Format: reportv1.ReportFormat(reportv1.ReportFormat_value["REPORT_FORMAT_"+strings.ToUpper(v.Format)]), Filter: gatewayAnalyticsFilter(v.Filter)})
	dispatchResponse(c, http.StatusAccepted, e, x)
}
func (h *ReportHandler) Get(c *gin.Context) {
	var v models.GetReportRequest
	if !bindJSON(c, &v) {
		return
	}
	u, r := principal(c)
	x, e := h.client.GetReport(dispatchContext(c), &reportv1.GetReportRequest{ReportId: v.ReportID, ActorUserId: u, ActorRoles: r})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *ReportHandler) List(c *gin.Context) {
	var v models.ListReportsRequest
	if !bindJSON(c, &v) {
		return
	}
	u, r := principal(c)
	q := &reportv1.ListReportsRequest{ActorUserId: u, ActorRoles: r, Limit: v.Limit, Offset: v.Offset}
	if v.Status != nil {
		x := reportv1.ReportStatus(reportv1.ReportStatus_value["REPORT_STATUS_"+strings.ToUpper(*v.Status)])
		q.Status = &x
	}
	x, e := h.client.ListReports(dispatchContext(c), q)
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *ReportHandler) Cancel(c *gin.Context) {
	var v models.GetReportRequest
	if !bindJSON(c, &v) {
		return
	}
	u, r := principal(c)
	x, e := h.client.CancelReport(dispatchContext(c), &reportv1.CancelReportRequest{ReportId: v.ReportID, ActorUserId: u, ActorRoles: r})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *ReportHandler) Retry(c *gin.Context) {
	var v models.GetReportRequest
	if !bindJSON(c, &v) {
		return
	}
	u, r := principal(c)
	x, e := h.client.RetryReport(dispatchContext(c), &reportv1.RetryReportRequest{ReportId: v.ReportID, ActorUserId: u, ActorRoles: r})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *ReportHandler) Download(c *gin.Context) {
	var v models.GetReportRequest
	if !bindJSON(c, &v) {
		return
	}
	u, r := principal(c)
	x, e := h.client.GetReportDownloadURL(dispatchContext(c), &reportv1.GetReportDownloadURLRequest{ReportId: v.ReportID, ActorUserId: u, ActorRoles: r})
	dispatchResponse(c, http.StatusOK, e, x)
}
func principal(c *gin.Context) (string, []string) { return c.GetString("user_id"), actorRoles(c) }
func gatewayAnalyticsFilter(v *models.AnalyticsFilter) *analyticsv1.AnalyticsFilter {
	return analyticsFilter(v)
}
