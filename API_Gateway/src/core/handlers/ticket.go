package handlers

import (
	"context"
	"gateway/models"
	"net/http"
	"strings"
	"time"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type TicketHandler struct {
	ticketClient  ticketv1.TicketServiceClient
	brigadeClient brigadev1.BrigadeServiceClient
	profileClient profilev1.ProfileServiceClient
}

// NewTicketHandler создает обработчик операций с билетами и отчетами.
func NewTicketHandler(ticketClient ticketv1.TicketServiceClient, brigadeClient brigadev1.BrigadeServiceClient, profileClient profilev1.ProfileServiceClient) *TicketHandler {
	return &TicketHandler{ticketClient: ticketClient, brigadeClient: brigadeClient, profileClient: profileClient}
}

// CreateWorkReport создает рабочий отчет по билету.
func (th *TicketHandler) CreateWorkReport(c *gin.Context) {
	var req models.CreateWorkReportRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx, ok := th.contextWithWorkerBrigade(ctx, c)

	if !ok {
		return
	}

	res, err := th.ticketClient.CreateWorkReport(ctx, &ticketv1.CreateWorkReportRequest{
		TicketId:     req.TicketID,
		AuthorUserId: c.GetString("user_id"),
		Description:  req.Description,
		FileIds:      req.FileIDs,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, fromProtoWorkReport(res.GetReport()))
}

// actorHasRole проверяет роль текущего пользователя.
func actorHasRole(c *gin.Context, expected string) bool {
	roles, _ := c.Get("roles")
	values, _ := roles.([]string)
	for _, role := range values {

		if role == expected {
			return true
		}

	}
	return false
}

// contextWithWorkerBrigade добавляет в контекст бригаду сотрудника, если она определена.
func (th *TicketHandler) contextWithWorkerBrigade(ctx context.Context, c *gin.Context) (context.Context, bool) {
	ctx = ticketActorContext(ctx, c)
	if actorHasRole(c, "dispatcher") && !actorHasRole(c, "admin") {
		resolved, err := th.profileClient.ResolveWorkingDepartment(ctx, &profilev1.ResolveWorkingDepartmentRequest{UserId: c.GetString("user_id")})
		if err != nil {
			handleGRPCError(c, err)
			return ctx, false
		}
		if !resolved.GetCanOperate() || resolved.GetDepartmentId() == "" {
			writeAPIError(c, http.StatusForbidden, "PERMISSION_DENIED", "Рабочий профиль не разрешает операции")
			return ctx, false
		}
		ctx = metadata.AppendToOutgoingContext(ctx, "x-actor-department-id", resolved.GetDepartmentId())
	}

	if !actorHasRole(c, "worker") {
		return ctx, true
	}

	onlyActive := true
	own, err := th.brigadeClient.GetBrigadeByUserID(ctx, &brigadev1.GetBrigadeByUserIDRequest{UserId: c.GetString("user_id"), OnlyActive: &onlyActive})

	if err != nil {
		handleGRPCError(c, err)
		return ctx, false
	}

	return metadata.AppendToOutgoingContext(ctx, "x-actor-brigade-id", own.GetBrigade().GetId()), true
}

// ListWorkReports возвращает рабочие отчеты по билету.
func (th *TicketHandler) ListWorkReports(c *gin.Context) {
	var req models.ListWorkReportsRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx, ok := th.contextWithWorkerBrigade(ctx, c)

	if !ok {
		return
	}

	res, err := th.ticketClient.ListWorkReports(ctx, &ticketv1.ListWorkReportsRequest{TicketId: req.TicketID})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	reports := make([]*models.WorkReport, 0, len(res.GetReports()))
	for _, r := range res.GetReports() {
		reports = append(reports, fromProtoWorkReport(r))
	}
	c.JSON(http.StatusOK, gin.H{"reports": reports})
}

// fromProtoWorkReport преобразует рабочий отчет protobuf в модель Gateway.
func fromProtoWorkReport(r *ticketv1.WorkReport) *models.WorkReport {

	if r == nil {
		return nil
	}

	return &models.WorkReport{
		ID:               r.GetId(),
		TicketID:         r.GetTicketId(),
		AuthorUserID:     r.GetAuthorUserId(),
		Description:      r.GetDescription(),
		FileIDs:          r.GetFileIds(),
		CreatedAt:        r.GetCreatedAt().AsTime(),
		UpdatedAt:        r.GetUpdatedAt().AsTime(),
		CompletionStatus: r.GetCompletionStatus(),
		CompletionFileID: r.GetCompletionFileId(),
		CompletionError:  r.GetCompletionError(),
	}
}

// CreateTicket создает новый билет.
func (th *TicketHandler) CreateTicket(c *gin.Context) {
	var req models.CreateTicketRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

	res, err := th.ticketClient.CreateTicket(ctx, &ticketv1.CreateTicketRequest{
		DepartmentId: req.DepartmentID,
		CategoryId:   req.CategoryID,
		UserId:       c.GetString("user_id"),
		Title:        req.Title,
		Description:  req.Description,
		Priority:     ToProtoPriority(req.Priority),
		Address:      req.Address,
		Latitude:     req.Latitude,
		Longitude:    req.Longitude,
		AssetId:      req.AssetID,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusCreated, &models.CreateTicketResponse{
		Ticket: FromProtoTicket(res.GetTicket()),
	})
}

// GetTicket возвращает билет по идентификатору.
func (th *TicketHandler) GetTicket(c *gin.Context) {
	var req models.GetTicketRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx, ok := th.contextWithWorkerBrigade(ctx, c)

	if !ok {
		return
	}

	res, err := th.ticketClient.GetTicket(ctx, &ticketv1.GetTicketRequest{
		TicketId: req.TicketID,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.GetTicketResponse{
		Ticket: FromProtoTicket(res.GetTicket()),
	})
}

// ListTicket возвращает список билетов с фильтрами.
func (th *TicketHandler) ListTicket(c *gin.Context) {
	var req models.ListTicketRequest

	if !bindJSON(c, &req) {
		return
	}

	protoReq, ok := buildListTicketsRequest(c, &req)

	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx, ok = th.contextWithWorkerBrigade(ctx, c)
	if !ok {
		return
	}

	res, err := th.ticketClient.ListTickets(ctx, protoReq)

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	tickets := make([]*models.Ticket, 0, len(res.GetTickets()))
	for _, ticket := range res.GetTickets() {
		tickets = append(tickets, FromProtoTicket(ticket))
	}

	c.JSON(http.StatusOK, &models.ListTicketResponse{
		Tickets: tickets,
		Total:   res.GetTotal(),
	})
}

// UpdateTicket изменяет данные билета.
func (th *TicketHandler) UpdateTicket(c *gin.Context) {
	var req models.UpdateTicketRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx, ok := th.contextWithWorkerBrigade(ctx, c)
	if !ok {
		return
	}

	if roleValues, _ := c.Get("roles"); hasTicketRole(roleValues, "worker") {
		// The verified brigade was already attached above.
	}

	res, err := th.ticketClient.UpdateTicket(ctx, buildUpdateTicketRequest(&req, c.GetString("user_id")))

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.UpdateTicketResponse{
		Ticket: FromProtoTicket(res.GetTicket()),
	})
}

// hasTicketRole проверяет роль в значении произвольного типа.
func hasTicketRole(value any, wanted string) bool {
	roles, ok := value.([]string)

	if !ok {
		return false
	}

	for _, role := range roles {

		if role == wanted {
			return true
		}

	}
	return false
}

// ChangeTicketStatus изменяет статус билета.
func (th *TicketHandler) ChangeTicketStatus(c *gin.Context) {
	var req models.ChangeTicketStatusRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx, ok := th.contextWithWorkerBrigade(ctx, c)

	if !ok {
		return
	}

	res, err := th.ticketClient.ChangeTicketStatus(ctx, &ticketv1.ChangeTicketStatusRequest{
		TicketId:  req.TicketID,
		NewStatus: ToProtoStatus(req.NewStatus),
		ChangedBy: c.GetString("user_id"),
		Comment:   req.Comment,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.ChangeTicketStatusResponse{
		Ticket: FromProtoTicket(res.GetTicket()),
	})
}

// AssignBrigade назначает бригаду на билет.
func (th *TicketHandler) AssignBrigade(c *gin.Context) {
	var req models.AssignBrigadeRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx, ok := th.contextWithWorkerBrigade(ctx, c)
	if !ok {
		return
	}

	res, err := th.ticketClient.AssignBrigade(ctx, &ticketv1.AssignBrigadeRequest{
		TicketId:   req.TicketID,
		BrigadeId:  req.BrigadeID,
		AssignedBy: c.GetString("user_id"),
		Comment:    req.Comment,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.AssignBrigadeResponse{
		Ticket: FromProtoTicket(res.GetTicket()),
	})
}

// CancelTicket отменяет билет.
func (th *TicketHandler) CancelTicket(c *gin.Context) {
	var req models.CancelTicketRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx, ok := th.contextWithWorkerBrigade(ctx, c)
	if !ok {
		return
	}

	res, err := th.ticketClient.CancelTicket(ctx, &ticketv1.CancelTicketRequest{
		TicketId:   req.TicketID,
		CanceledBy: c.GetString("user_id"),
		Reason:     req.Reason,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.CancelTicketResponse{
		Ticket: FromProtoTicket(res.GetTicket()),
	})
}

// CompleteTicket завершает билет.
func (th *TicketHandler) CompleteTicket(c *gin.Context) {
	var req models.CompleteTicketRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx, ok := th.contextWithWorkerBrigade(ctx, c)

	if !ok {
		return
	}

	res, err := th.ticketClient.CompleteTicket(ctx, &ticketv1.CompleteTicketRequest{
		TicketId:    req.TicketID,
		CompletedBy: c.GetString("user_id"),
		Comment:     stringOrEmpty(req.Comment),
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.CompleteTicketResponse{
		Ticket: FromProtoTicket(res.GetTicket()),
	})
}

// GetTicketStatusHistory возвращает историю статусов билета.
func (th *TicketHandler) GetTicketStatusHistory(c *gin.Context) {
	var req models.GetTicketStatusHistoryRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx, ok := th.contextWithWorkerBrigade(ctx, c)

	if !ok {
		return
	}

	res, err := th.ticketClient.GetTicketStatusHistory(ctx, &ticketv1.GetTicketStatusHistoryRequest{
		TicketId: req.TicketID,
		Limit:    int32OrZero(req.Limit),
		Offset:   int32OrZero(req.Offset),
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	history := make([]*models.TicketStatusHistory, 0, len(res.GetHistory()))
	for _, item := range res.GetHistory() {
		history = append(history, FromProtoStatusHistory(item))
	}

	c.JSON(http.StatusOK, &models.GetTicketStatusHistoryResponse{
		History: history,
		Total:   res.GetTotal(),
	})
}

// CreateCategory создает категорию билетов.
func (th *TicketHandler) CreateCategory(c *gin.Context) {
	var req models.CreateCategoryRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

	res, err := th.ticketClient.CreateCategory(ctx, &ticketv1.CreateCategoryRequest{
		Code:        req.Code,
		Name:        req.Name,
		Description: stringOrEmpty(req.Description),
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusCreated, &models.CreateCategoryResponse{
		Category: FromProtoCategory(res.GetCategory()),
	})
}

// GetCategory возвращает категорию по идентификатору.
func (th *TicketHandler) GetCategory(c *gin.Context) {
	var req models.GetCategoryRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

	res, err := th.ticketClient.GetCategory(ctx, &ticketv1.GetCategoryRequest{
		CategoryId: req.CategoryID,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.GetCategoryResponse{
		Category: FromProtoCategory(res.GetCategory()),
	})
}

// ListCategories возвращает список категорий.
func (th *TicketHandler) ListCategories(c *gin.Context) {
	var req models.ListCategoriesRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

	res, err := th.ticketClient.ListCategories(ctx, &ticketv1.ListCategoriesRequest{
		OnlyActive: req.OnlyActive,
		Limit:      int32OrZero(req.Limit),
		Offset:     int32OrZero(req.Offset),
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	categories := make([]*models.TicketCategory, 0, len(res.GetCategories()))
	for _, category := range res.GetCategories() {
		categories = append(categories, FromProtoCategory(category))
	}

	c.JSON(http.StatusOK, &models.ListCategoriesResponse{
		Categories: categories,
		Total:      res.GetTotal(),
	})
}

// UpdateCategory изменяет категорию.
func (th *TicketHandler) UpdateCategory(c *gin.Context) {
	var req models.UpdateCategoryRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

	res, err := th.ticketClient.UpdateCategory(ctx, &ticketv1.UpdateCategoryRequest{
		CategoryId:  req.CategoryID,
		Name:        req.Name,
		Description: req.Description,
		IsActive:    req.IsActive,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.UpdateCategoryResponse{
		Category: FromProtoCategory(res.GetCategory()),
	})
}

// DeleteCategory удаляет категорию.
func (th *TicketHandler) DeleteCategory(c *gin.Context) {
	var req models.DeleteCategoryRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

	res, err := th.ticketClient.DeleteCategory(ctx, &ticketv1.DeleteCategoryRequest{
		CategoryId: req.CategoryID,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.DeleteCategoryResponse{
		Category: FromProtoCategory(res.GetCategory()),
	})
}

// CreateRequest создает запрос, связанный с инцидентом.
func (th *TicketHandler) CreateRequest(c *gin.Context) {
	var req models.CreateRequestRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	ctx = ticketActorContext(ctx, c)

	response, err := th.ticketClient.CreateRequest(ctx, &ticketv1.CreateRequestRequest{
		DepartmentId: req.DepartmentID,
		CategoryId:   req.CategoryID,
		UserId:       c.GetString("user_id"),
		Title:        req.Title,
		Description:  req.Description,
		Priority:     ToProtoPriority(req.Priority),
		Address:      req.Address,
		Latitude:     req.Latitude,
		Longitude:    req.Longitude,
		AssetId:      req.AssetID,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusCreated, &models.CreateRequestResponse{
		Request:          FromProtoTicket(response.GetRequest()),
		Incident:         FromProtoTicket(response.GetIncident()),
		DuplicateMatched: response.GetDuplicateMatched(),
	})
}

// AttachRequest прикрепляет запрос к инциденту.
func (th *TicketHandler) AttachRequest(c *gin.Context) {
	var req models.AttachRequestRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	ctx, ok := th.contextWithWorkerBrigade(ctx, c)

	if !ok {
		return
	}

	response, err := th.ticketClient.AttachRequest(ctx, &ticketv1.AttachRequestRequest{
		IncidentId: req.IncidentID,
		RequestId:  req.RequestID,
		Reason:     req.Reason,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"request": FromProtoTicket(response.GetRequest())})
}

// DetachRequest открепляет запрос от инцидента.
func (th *TicketHandler) DetachRequest(c *gin.Context) {
	var req models.DetachRequestRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	ctx, ok := th.contextWithWorkerBrigade(ctx, c)

	if !ok {
		return
	}

	response, err := th.ticketClient.DetachRequest(ctx, &ticketv1.DetachRequestRequest{
		RequestId: req.RequestID,
		Reason:    req.Reason,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"request": FromProtoTicket(response.GetRequest())})
}

// ListIncidentRequests возвращает запросы инцидента.
func (th *TicketHandler) ListIncidentRequests(c *gin.Context) {
	var req models.ListIncidentRequestsRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	ctx, ok := th.contextWithWorkerBrigade(ctx, c)

	if !ok {
		return
	}

	response, err := th.ticketClient.ListIncidentRequests(ctx, &ticketv1.ListIncidentRequestsRequest{
		IncidentId: req.IncidentID,
		Limit:      int32OrZero(req.Limit),
		Offset:     int32OrZero(req.Offset),
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	allRequests := response.GetRequests()

	if response.GetTotal() > int64(len(allRequests)) || int32OrZero(req.Offset) > 0 {
		allRequests = make([]*ticketv1.Ticket, 0, int(response.GetTotal()))

		for offset := int32(0); int64(offset) < response.GetTotal(); offset += 100 {
			page, pageErr := th.ticketClient.ListIncidentRequests(ctx, &ticketv1.ListIncidentRequestsRequest{
				IncidentId: req.IncidentID,
				Limit:      100,
				Offset:     offset,
			})

			if pageErr != nil {
				handleGRPCError(c, pageErr)
				return
			}

			allRequests = append(allRequests, page.GetRequests()...)

			if len(page.GetRequests()) < 100 {
				break
			}
		}
	}

	requests := make([]*models.Ticket, 0, len(response.GetRequests()))
	departments := make(map[string]struct{})
	var completed int64

	for _, request := range allRequests {
		mapped := FromProtoTicket(request)
		departments[mapped.DepartmentID] = struct{}{}

		if mapped.Status == "DONE" {
			completed++
		}
	}

	for _, request := range response.GetRequests() {
		requests = append(requests, FromProtoTicket(request))
	}

	c.JSON(http.StatusOK, &models.ListIncidentRequestsResponse{
		Requests:          requests,
		Total:             response.GetTotal(),
		Completed:         completed,
		DepartmentCount:   len(departments),
		IsComposite:       len(departments) > 1,
		AllPartsCompleted: response.GetTotal() > 0 && completed == response.GetTotal(),
	})
}

// RegisterIntegration регистрирует внешнюю интеграцию билетов.
func (th *TicketHandler) RegisterIntegration(c *gin.Context) {
	var req models.RegisterTicketIntegrationRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	ctx = ticketActorContext(ctx, c)

	response, err := th.ticketClient.RegisterIntegration(ctx, &ticketv1.RegisterIntegrationRequest{
		Name:                req.Name,
		ClientId:            req.ClientID,
		AllowedDepartmentId: req.AllowedDepartmentID,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusCreated, &models.RegisterTicketIntegrationResponse{
		Integration: fromProtoTicketIntegration(response.GetIntegration()),
		Secret:      response.GetSecret(),
	})
}

// ListIntegrations возвращает зарегистрированные интеграции.
func (th *TicketHandler) ListIntegrations(c *gin.Context) {
	var req models.ListTicketIntegrationsRequest
	if !bindJSON(c, &req) {
		return
	}

	limit := int32(50)
	if req.Limit != nil {
		limit = *req.Limit
	}
	offset := int32(0)
	if req.Offset != nil {
		offset = *req.Offset
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	response, err := th.ticketClient.ListIntegrations(
		ticketActorContext(ctx, c),
		&ticketv1.ListIntegrationsRequest{Limit: limit, Offset: offset},
	)
	if err != nil {
		handleGRPCError(c, err)
		return
	}

	integrations := make([]*models.TicketIntegration, 0, len(response.GetIntegrations()))
	for _, integration := range response.GetIntegrations() {
		integrations = append(integrations, fromProtoTicketIntegration(integration))
	}

	c.JSON(http.StatusOK, &models.ListTicketIntegrationsResponse{
		Integrations: integrations,
		Total:        response.GetTotal(),
	})
}

// SetIntegrationActive изменяет активность интеграции.
func (th *TicketHandler) SetIntegrationActive(c *gin.Context) {
	var req models.SetTicketIntegrationActiveRequest
	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	response, err := th.ticketClient.SetIntegrationActive(
		ticketActorContext(ctx, c),
		&ticketv1.SetIntegrationActiveRequest{
			IntegrationId: req.IntegrationID,
			IsActive:      *req.IsActive,
		},
	)
	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"integration": fromProtoTicketIntegration(response.GetIntegration())})
}

// RotateIntegrationSecret обновляет секрет интеграции.
func (th *TicketHandler) RotateIntegrationSecret(c *gin.Context) {
	var req models.RotateTicketIntegrationSecretRequest
	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	response, err := th.ticketClient.RotateIntegrationSecret(
		ticketActorContext(ctx, c),
		&ticketv1.RotateIntegrationSecretRequest{IntegrationId: req.IntegrationID},
	)
	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.RegisterTicketIntegrationResponse{
		Integration: fromProtoTicketIntegration(response.GetIntegration()),
		Secret:      response.GetSecret(),
	})
}

// CreateExternalRequest создает запрос через внешнюю интеграцию.
func (th *TicketHandler) CreateExternalRequest(c *gin.Context) {
	var req models.CreateExternalTicketRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	response, err := th.ticketClient.CreateExternalRequest(ctx, &ticketv1.CreateExternalRequestRequest{
		ClientId:     req.ClientID,
		Secret:       req.Secret,
		ExternalId:   req.ExternalID,
		DepartmentId: req.DepartmentID,
		CategoryId:   req.CategoryID,
		UserId:       req.UserID,
		Title:        req.Title,
		Description:  req.Description,
		Priority:     ToProtoPriority(req.Priority),
		Address:      req.Address,
		Latitude:     req.Latitude,
		Longitude:    req.Longitude,
		AssetId:      req.AssetID,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusCreated, &models.CreateRequestResponse{
		Request:          FromProtoTicket(response.GetRequest()),
		Incident:         FromProtoTicket(response.GetIncident()),
		DuplicateMatched: response.GetDuplicateMatched(),
	})
}

// fromProtoTicketIntegration преобразует интеграцию protobuf в модель Gateway.
func fromProtoTicketIntegration(value *ticketv1.TicketIntegration) *models.TicketIntegration {

	if value == nil {
		return nil
	}

	return &models.TicketIntegration{
		ID:                  value.GetId(),
		Name:                value.GetName(),
		ClientID:            value.GetClientId(),
		SecretPrefix:        value.GetSecretPrefix(),
		AllowedDepartmentID: value.GetAllowedDepartmentId(),
		IsActive:            value.GetIsActive(),
		CreatedBy:           value.GetCreatedBy(),
		CreatedAt:           timestampTime(value.GetCreatedAt()),
		UpdatedAt:           timestampTime(value.GetUpdatedAt()),
		LastUsedAt:          timestampTime(value.GetLastUsedAt()),
	}
}

// timestampTime преобразует protobuf-время в time.Time, возвращая нулевое время для nil.
func timestampTime(value *timestamppb.Timestamp) time.Time {

	if value == nil {
		return time.Time{}
	}

	return value.AsTime()
}

// bindJSON разбирает JSON-тело и отправляет клиенту ошибку 400 при неверном формате.
func bindJSON(c *gin.Context, req any) bool {

	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return false
	}

	return true
}

// buildListTicketsRequest преобразует параметры списка в запрос Ticket API.
func buildListTicketsRequest(c *gin.Context, req *models.ListTicketRequest) (*ticketv1.ListTicketsRequest, bool) {
	protoReq := &ticketv1.ListTicketsRequest{
		DepartmentId: req.DepartmentID,
		UserId:       req.UserID,
		BrigadeId:    req.BrigadeID,
		CategoryId:   req.CategoryID,
		Limit:        int32OrZero(req.Limit),
		Offset:       int32OrZero(req.Offset),
	}

	if req.Status != nil {
		status := ToProtoStatus(*req.Status)
		protoReq.Status = &status
	}

	if req.Priority != nil {
		priority := ToProtoPriority(*req.Priority)
		protoReq.Priority = &priority
	}

	if req.SortBy != nil {
		sortBy := ToProtoSortBy(*req.SortBy)
		protoReq.SortBy = &sortBy
	}

	if req.SortOrder != nil {
		sortOrder := ToProtoSortOrder(*req.SortOrder)
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

// buildUpdateTicketRequest преобразует модель обновления в protobuf-запрос.
func buildUpdateTicketRequest(req *models.UpdateTicketRequest, updatedBy string) *ticketv1.UpdateTicketRequest {
	protoReq := &ticketv1.UpdateTicketRequest{
		TicketId:    req.TicketID,
		Title:       req.Title,
		Description: req.Description,
		CategoryId:  req.CategoryID,
		Address:     req.Address,
		Latitude:    req.Latitude,
		Longitude:   req.Longitude,
		AssetId:     req.AssetID,
		UpdatedBy:   updatedBy,
	}

	if req.Priority != nil {
		priority := ToProtoPriority(*req.Priority)
		protoReq.Priority = &priority
	}

	return protoReq
}

// stringOrEmpty возвращает значение указателя или пустую строку для nil.
func stringOrEmpty(value *string) string {

	if value == nil {
		return ""
	}

	return *value
}

// int32OrZero возвращает значение указателя или ноль для nil.
func int32OrZero(value *int32) int32 {

	if value == nil {
		return 0
	}

	return *value
}

// ticketActorContext добавляет в контекст исходящие метаданные текущего пользователя.
func ticketActorContext(ctx context.Context, c *gin.Context) context.Context {
	roles, _ := c.Get("roles")
	roleValues, _ := roles.([]string)

	return metadata.AppendToOutgoingContext(
		ctx,
		"x-actor-user-id", c.GetString("user_id"),
		"x-actor-roles", strings.Join(roleValues, ","),
	)
}
