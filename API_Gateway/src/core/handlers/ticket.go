package handlers

import (
	"context"
	"gateway/models"
	"net/http"
	"strings"
	"time"

	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/metadata"
)

type TicketHandler struct {
	ticketClient ticketv1.TicketServiceClient
}

func NewTicketHandler(ticketClient ticketv1.TicketServiceClient) *TicketHandler {
	return &TicketHandler{ticketClient: ticketClient}
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
		Latitude:     valueOrZero(req.Latitude),
		Longitude:    valueOrZero(req.Longitude),
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
	ctx = ticketActorContext(ctx, c)

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

	res, err := th.ticketClient.UpdateTicket(ctx, buildUpdateTicketRequest(&req, c.GetString("user_id")))
	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.UpdateTicketResponse{
		Ticket: FromProtoTicket(res.GetTicket()),
	})
}

func (th *TicketHandler) ChangeTicketStatus(c *gin.Context) {
	var req models.ChangeTicketStatusRequest
	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

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
	ctx = ticketActorContext(ctx, c)

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
	ctx = ticketActorContext(ctx, c)

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
		OnlyActive: boolOrDefault(req.OnlyActive, false),
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
		Name:        stringOrEmpty(req.Name),
		Description: stringOrEmpty(req.Description),
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
		DepartmentId: stringOrEmpty(req.DepartmentID),
		UserId:       stringOrEmpty(req.UserID),
		BrigadeId:    stringOrEmpty(req.BrigadeID),
		CategoryId:   stringOrEmpty(req.CategoryID),
		Limit:        int32OrZero(req.Limit),
		Offset:       int32OrZero(req.Offset),
	}

	if req.Status != nil {
		protoReq.Status = ToProtoStatus(*req.Status)
	}
	if req.Priority != nil {
		protoReq.Priority = ToProtoPriority(*req.Priority)
	}
	if req.SortBy != nil {
		protoReq.SortBy = ToProtoSortBy(*req.SortBy)
	}
	if req.SortOrder != nil {
		protoReq.SortOrder = ToProtoSortOrder(*req.SortOrder)
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
		Title:       stringOrEmpty(req.Title),
		Description: stringOrEmpty(req.Description),
		CategoryId:  stringOrEmpty(req.CategoryID),
		Address:     stringOrEmpty(req.Address),
		Latitude:    req.Latitude,
		Longitude:   req.Longitude,
		UpdatedBy:   updatedBy,
	}

	if req.Priority != nil {
		protoReq.Priority = ToProtoPriority(*req.Priority)
	}

	return protoReq
}

func stringOrEmpty(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}

func valueOrZero(value *float64) float64 {
	if value == nil {
		return 0
	}

	return *value
}

func int32OrZero(value *int32) int32 {
	if value == nil {
		return 0
	}

	return *value
}

func boolOrDefault(value *bool, defaultValue bool) bool {
	if value == nil {
		return defaultValue
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
