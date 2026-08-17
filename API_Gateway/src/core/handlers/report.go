package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"gateway/models"
	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	reportv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/report/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"
)

type ReportHandler struct {
	client        reportv1.ReportServiceClient
	tickets       ticketv1.TicketServiceClient
	brigades      brigadev1.BrigadeServiceClient
	profiles      profilev1.ProfileServiceClient
	internalURL   string
	internalToken string
	httpClient    *http.Client
}

func NewReportHandler(c reportv1.ReportServiceClient, tickets ticketv1.TicketServiceClient, brigades brigadev1.BrigadeServiceClient, profiles profilev1.ProfileServiceClient, internalURL, internalToken string) *ReportHandler {
	return &ReportHandler{client: c, tickets: tickets, brigades: brigades, profiles: profiles, internalURL: strings.TrimRight(internalURL, "/"), internalToken: internalToken, httpClient: &http.Client{Timeout: 45 * time.Second}}
}

type completionReportRequest struct {
	WorkReportID string            `json:"work_report_id"`
	RequestedBy  string            `json:"requested_by"`
	ActorRoles   []string          `json:"actor_roles"`
	Ticket       completionTicket  `json:"ticket"`
	Brigade      completionBrigade `json:"brigade"`
	OpenedBy     string            `json:"opened_by"`
	Description  string            `json:"description"`
	FileIDs      []string          `json:"file_ids"`
}

type completionTicket struct{ ID, Title, Address string }
type completionBrigade struct {
	ID      string                    `json:"id"`
	Name    string                    `json:"name"`
	Members []completionBrigadeMember `json:"members"`
}
type completionBrigadeMember struct {
	UserID   string `json:"user_id"`
	FullName string `json:"full_name"`
	Role     string `json:"role"`
}

func (h *ReportHandler) CreateCompletion(c *gin.Context) {
	var input models.CreateWorkReportRequest
	if !bindJSON(c, &input) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()
	actorCtx, ok := h.contextWithWorkerBrigade(ctx, c)
	if !ok {
		return
	}
	ticketResult, err := h.tickets.GetTicket(actorCtx, &ticketv1.GetTicketRequest{TicketId: input.TicketID})
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	ticket := ticketResult.GetTicket()
	payload := completionReportRequest{
		RequestedBy: c.GetString("user_id"),
		ActorRoles:  actorRoles(c),
		Ticket:      completionTicket{ID: ticket.GetId(), Title: ticket.GetTitle(), Address: ticket.GetAddress()},
		OpenedBy:    h.profileName(actorCtx, ticket.GetUserId()),
		Description: input.Description,
		FileIDs:     input.FileIDs,
	}
	if brigadeID := ticket.GetBrigadeId(); brigadeID != "" {
		payload.Brigade.ID = brigadeID
		if result, brigadeErr := h.brigades.GetBrigadeByID(actorCtx, &brigadev1.GetBrigadeByIDRequest{Id: brigadeID}); brigadeErr == nil && result.GetBrigade() != nil {
			payload.Brigade.Name = result.GetBrigade().GetName()
		}
		active := true
		if result, membersErr := h.brigades.ListBrigadeMembers(actorCtx, &brigadev1.ListBrigadeMembersRequest{BrigadeId: brigadeID, Active: &active, Limit: 100}); membersErr == nil {
			for _, member := range result.GetMembers() {
				payload.Brigade.Members = append(payload.Brigade.Members, completionBrigadeMember{UserID: member.GetUserId(), FullName: h.profileName(actorCtx, member.GetUserId()), Role: completionRole(member.GetRole())})
			}
		}
	}
	// Perform all permission-sensitive reads before persisting the work report.
	// This prevents a rejected completion request from leaving a duplicate,
	// file-less report in the ticket history.
	workReportResult, err := h.tickets.CreateWorkReport(actorCtx, &ticketv1.CreateWorkReportRequest{TicketId: input.TicketID, AuthorUserId: c.GetString("user_id"), Description: input.Description, FileIds: input.FileIDs})
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	workReport := workReportResult.GetReport()
	payload.WorkReportID = workReport.GetId()
	encoded, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to prepare completion report"})
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, h.internalURL+"/internal/completion-reports", bytes.NewReader(encoded))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to prepare completion report"})
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Report-Internal-Token", h.internalToken)
	response, err := h.httpClient.Do(request)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "report service unavailable"})
		return
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode/100 != 2 {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("report service returned %s", response.Status)})
		return
	}
	var generated struct {
		FileID string `json:"file_id"`
		Name   string `json:"name"`
	}
	if err := json.Unmarshal(data, &generated); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid report service response"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"work_report": fromProtoWorkReport(workReport), "pdf_file_id": generated.FileID, "pdf_name": generated.Name})
}

func (h *ReportHandler) contextWithWorkerBrigade(ctx context.Context, c *gin.Context) (context.Context, bool) {
	ctx = gatewayActorContext(ctx, c)
	if !actorHasRole(c, "worker") {
		return ctx, true
	}
	onlyActive := true
	result, err := h.brigades.GetBrigadeByUserID(ctx, &brigadev1.GetBrigadeByUserIDRequest{UserId: c.GetString("user_id"), OnlyActive: &onlyActive})
	if err != nil {
		handleGRPCError(c, err)
		return ctx, false
	}
	return metadata.AppendToOutgoingContext(ctx, "x-actor-brigade-id", result.GetBrigade().GetId()), true
}

func (h *ReportHandler) profileName(ctx context.Context, userID string) string {
	if strings.TrimSpace(userID) == "" {
		return "Не указан"
	}
	result, err := h.profiles.GetUserProfileByUserID(ctx, &profilev1.GetUserProfileByUserIDRequest{UserId: userID})
	if err == nil && result.GetUserProfile() != nil && strings.TrimSpace(result.GetUserProfile().GetFullName()) != "" {
		return result.GetUserProfile().GetFullName()
	}
	return userID
}

func completionRole(role brigadev1.BrigadeMemberRole) string {
	switch role {
	case brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_LEAD:
		return "руководитель"
	case brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_TECHNICIAN:
		return "специалист"
	default:
		return "участник"
	}
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
