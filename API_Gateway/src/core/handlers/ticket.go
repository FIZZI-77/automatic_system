package handlers

import (
	"context"
	"gateway/models"
	"net/http"
	"strings"
	"time"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/metadata"
)

type TicketHandler struct {
	ticketClient  ticketv1.TicketServiceClient
	brigadeClient brigadev1.BrigadeServiceClient
}

func NewTicketHandler(ticketClient ticketv1.TicketServiceClient, brigadeClient brigadev1.BrigadeServiceClient) *TicketHandler {
	return &TicketHandler{ticketClient: ticketClient, brigadeClient: brigadeClient}
}

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
	res, err := th.ticketClient.CreateWorkReport(ctx, &ticketv1.CreateWorkReportRequest{TicketId: req.TicketID, AuthorUserId: c.GetString("user_id"), Description: req.Description, FileIds: req.FileIDs})
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, fromProtoWorkReport(res.GetReport()))
}

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

func (th *TicketHandler) contextWithWorkerBrigade(ctx context.Context, c *gin.Context) (context.Context, bool) {
	ctx = ticketActorContext(ctx, c)
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
func fromProtoWorkReport(r *ticketv1.WorkReport) *models.WorkReport {
	if r == nil {
		return nil
	}
	return &models.WorkReport{ID: r.GetId(), TicketID: r.GetTicketId(), AuthorUserID: r.GetAuthorUserId(), Description: r.GetDescription(), FileIDs: r.GetFileIds(), CreatedAt: r.GetCreatedAt().AsTime(), UpdatedAt: r.GetUpdatedAt().AsTime(), CompletionStatus: r.GetCompletionStatus(), CompletionFileID: r.GetCompletionFileId(), CompletionError: r.GetCompletionError()}
}

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
	ctx = ticketActorContext(ctx, c)
	if actorHasRole(c, "worker") {
		onlyActive := true
		own, err := th.brigadeClient.GetBrigadeByUserID(ctx, &brigadev1.GetBrigadeByUserIDRequest{UserId: c.GetString("user_id"), OnlyActive: &onlyActive})
		if err != nil {
			handleGRPCError(c, err)
			return
		}
		brigadeID := own.GetBrigade().GetId()
		protoReq.BrigadeId = &brigadeID
		ctx = metadata.AppendToOutgoingContext(ctx, "x-actor-brigade-id", brigadeID)
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

func (th *TicketHandler) UpdateTicket(c *gin.Context) {
	var req models.UpdateTicketRequest
	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)
	if roleValues, _ := c.Get("roles"); hasTicketRole(roleValues, "worker") {
		var ok bool
		ctx, ok = th.contextWithWorkerBrigade(ctx, c)
		if !ok {
			return
		}
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

func (th *TicketHandler) AssignBrigade(c *gin.Context) {
	var req models.AssignBrigadeRequest
	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

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

func (th *TicketHandler) CancelTicket(c *gin.Context) {
	var req models.CancelTicketRequest
	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

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

func bindJSON(c *gin.Context, req any) bool {
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return false
	}

	return true
}

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

func stringOrEmpty(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}

func int32OrZero(value *int32) int32 {
	if value == nil {
		return 0
	}

	return *value
}

func ticketActorContext(ctx context.Context, c *gin.Context) context.Context {
	roles, _ := c.Get("roles")
	roleValues, _ := roles.([]string)

	return metadata.AppendToOutgoingContext(
		ctx,
		"x-actor-user-id", c.GetString("user_id"),
		"x-actor-roles", strings.Join(roleValues, ","),
	)
}
