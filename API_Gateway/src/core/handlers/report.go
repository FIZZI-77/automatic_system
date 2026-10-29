package handlers

import (
	"context"
	"gateway/models"
	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	reportv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/report/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/gin-gonic/gin"
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

// NewReportHandler создаёт HTTP-обработчик отчётов с клиентами зависимостей;
// обрезает завершающие слеши internalURL и задаёт HTTP-клиенту таймаут 45 секунд.
func NewReportHandler(c reportv1.ReportServiceClient, tickets ticketv1.TicketServiceClient, brigades brigadev1.BrigadeServiceClient, profiles profilev1.ProfileServiceClient, internalURL, internalToken string) *ReportHandler {
	return &ReportHandler{
		client:        c,
		tickets:       tickets,
		brigades:      brigades,
		profiles:      profiles,
		internalURL:   strings.TrimRight(internalURL, "/"),
		internalToken: internalToken,
		httpClient:    &http.Client{Timeout: 45 * time.Second},
	}
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

// CreateCompletion разбирает JSON отчёта о работах, определяет бригаду работника
// и читает заявку до сохранения. Дополняет данные именами профилей и составом
// бригады, затем вызывает CreateWorkReport с ключом идемпотентности и данными завершения.
// При успехе возвращает HTTP 202, REPORT_PENDING и Location; общий таймаут — 45 секунд.
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
				payload.Brigade.Members = append(payload.Brigade.Members, completionBrigadeMember{
					UserID:   member.GetUserId(),
					FullName: h.profileName(actorCtx, member.GetUserId()),
					Role:     completionRole(member.GetRole()),
				})
			}
		}

	}

	// Чтение с проверкой доступа выполняется до сохранения отчёта, чтобы отказ
	// не оставил в истории повторный отчёт без файла завершения.
	completion := &ticketv1.CompletionReportRequest{
		RequestedBy: payload.RequestedBy,
		ActorRoles:  payload.ActorRoles,
		OpenedBy:    payload.OpenedBy,
		Brigade:     &ticketv1.CompletionBrigade{Id: payload.Brigade.ID, Name: payload.Brigade.Name},
	}
	for _, member := range payload.Brigade.Members {
		completion.Brigade.Members = append(completion.Brigade.Members, &ticketv1.CompletionBrigadeMember{UserId: member.UserID, FullName: member.FullName, Role: member.Role})
	}
	workReportResult, err := h.tickets.CreateWorkReport(actorCtx, &ticketv1.CreateWorkReportRequest{
		TicketId:       input.TicketID,
		AuthorUserId:   c.GetString("user_id"),
		Description:    input.Description,
		FileIds:        input.FileIDs,
		IdempotencyKey: c.GetHeader("Idempotency-Key"),
		Completion:     completion,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	workReport := workReportResult.GetReport()
	payload.WorkReportID = workReport.GetId()
	c.Header("Location", "/api/reports/"+workReport.GetId())
	c.JSON(http.StatusAccepted, gin.H{"work_report": fromProtoWorkReport(workReport), "status": "REPORT_PENDING"})
}

// contextWithWorkerBrigade добавляет метаданные пользователя, а для worker —
// ID его активной бригады из Brigade Service. При ошибке пишет HTTP-ответ;
// false требует прекратить обработку запроса.
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

// profileName запрашивает полное имя профиля; при ошибке или пустом имени
// возвращает userID, а для пустого или пробельного ID — «Не указан».
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

// completionRole возвращает русское название руководителя или специалиста;
// остальные роли, включая неизвестные, обозначает как «участник».
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

// Create преобразует JSON отчёта, тип, формат и фильтр, подставляет пользователя
// и роли из контекста и вызывает Report Service; при успехе возвращает HTTP 202.
func (h *ReportHandler) Create(c *gin.Context) {
	var v models.CreateReportRequest

	if !bindJSON(c, &v) {
		return
	}

	u, r := principal(c)
	x, e := h.client.CreateReport(dispatchContext(c), &reportv1.CreateReportRequest{
		RequestedBy: u,
		ActorRoles:  r,
		Name:        v.Name,
		Type:        reportv1.ReportType(reportv1.ReportType_value["REPORT_TYPE_"+strings.ToUpper(v.Type)]),
		Format:      reportv1.ReportFormat(reportv1.ReportFormat_value["REPORT_FORMAT_"+strings.ToUpper(v.Format)]),
		Filter:      gatewayAnalyticsFilter(v.Filter),
	})
	dispatchResponse(c, http.StatusAccepted, e, x)
}

// Get разбирает ID отчёта из JSON и запрашивает его с пользователем и ролями
// из контекста; успешный ответ возвращает с HTTP 200.
func (h *ReportHandler) Get(c *gin.Context) {
	var v models.GetReportRequest

	if !bindJSON(c, &v) {
		return
	}

	u, r := principal(c)
	x, e := h.client.GetReport(dispatchContext(c), &reportv1.GetReportRequest{ReportId: v.ReportID, ActorUserId: u, ActorRoles: r})
	dispatchResponse(c, http.StatusOK, e, x)
}

// List преобразует необязательный статус, передаёт пагинацию, пользователя
// и роли Report Service и возвращает его ответ с HTTP 200 при успехе.
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

// Cancel разбирает ID отчёта и передаёт отмену с пользователем и ролями сервису;
// успешный ответ возвращает с HTTP 200 через dispatchResponse.
func (h *ReportHandler) Cancel(c *gin.Context) {
	var v models.GetReportRequest

	if !bindJSON(c, &v) {
		return
	}

	u, r := principal(c)
	x, e := h.client.CancelReport(dispatchContext(c), &reportv1.CancelReportRequest{ReportId: v.ReportID, ActorUserId: u, ActorRoles: r})
	dispatchResponse(c, http.StatusOK, e, x)
}

// Retry разбирает ID отчёта и передаёт повтор формирования с пользователем
// и ролями сервису; при успехе возвращает HTTP 200.
func (h *ReportHandler) Retry(c *gin.Context) {
	var v models.GetReportRequest

	if !bindJSON(c, &v) {
		return
	}

	u, r := principal(c)
	x, e := h.client.RetryReport(dispatchContext(c), &reportv1.RetryReportRequest{ReportId: v.ReportID, ActorUserId: u, ActorRoles: r})
	dispatchResponse(c, http.StatusOK, e, x)
}

// Download разбирает ID отчёта и запрашивает ссылку скачивания с данными
// пользователя и ролями; возвращает ответ сервиса с HTTP 200 при успехе.
func (h *ReportHandler) Download(c *gin.Context) {
	var v models.GetReportRequest

	if !bindJSON(c, &v) {
		return
	}

	u, r := principal(c)
	x, e := h.client.GetReportDownloadURL(dispatchContext(c), &reportv1.GetReportDownloadURLRequest{ReportId: v.ReportID, ActorUserId: u, ActorRoles: r})
	dispatchResponse(c, http.StatusOK, e, x)
}

// principal возвращает ID пользователя и роли из Gin-контекста авторизации.
func principal(c *gin.Context) (string, []string) { return c.GetString("user_id"), actorRoles(c) }

// gatewayAnalyticsFilter преобразует необязательный фильтр отчёта общим analyticsFilter.
func gatewayAnalyticsFilter(v *models.AnalyticsFilter) *analyticsv1.AnalyticsFilter {
	return analyticsFilter(v)
}
