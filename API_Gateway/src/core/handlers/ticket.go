package handlers

import (
	"context"
	"gateway/models"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

type TicketHandler struct {
	ticketClient ticketv1.TicketServiceClient
}

func NewTicketHandler(ticketClient ticketv1.TicketServiceClient) *TicketHandler {
	return &TicketHandler{ticketClient: ticketClient}
}

func (th *TicketHandler) CreateTicket(c *gin.Context) {
	var req models.CreateTicketRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	res, err := th.ticketClient.CreateTicket(ctx, &ticketv1.CreateTicketRequest{
		DepartmentId: req.DepartmentID,
		CategoryId:   req.CategoryID,
		UserId:       req.UserID,
		Title:        req.Title,
		Description:  req.Description,
		Priority:     ToProtoPriority(req.Priority),
		Address:      req.Address,
		Latitude:     *req.Latitude,
		Longitude:    *req.Longitude,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	ticket := &models.Ticket{
		ID:              res.GetTicket().GetId(),
		DepartmentID:    res.GetTicket().GetDepartmentId(),
		CategoryID:      res.GetTicket().GetCategoryId(),
		UserID:          res.GetTicket().GetUserId(),
		BrigadeID:       res.GetTicket().GetBrigadeId(),
		Title:           res.GetTicket().GetTitle(),
		Description:     res.GetTicket().GetDescription(),
		Status:          string(res.GetTicket().GetStatus()),
		Priority:        string(res.GetTicket().GetPriority()),
		Address:         res.GetTicket().GetAddress(),
		Latitude:        res.GetTicket().GetLatitude(),
		Longitude:       res.GetTicket().GetLongitude(),
		CreatedAtUnix:   res.GetTicket().CreatedAt.AsTime().Unix(),
		UpdatedAtUnix:   res.GetTicket().UpdatedAt.AsTime().Unix(),
		AssignedAtUnix:  res.GetTicket().AssignedAt.AsTime().Unix(),
		CompletedAtUnix: res.GetTicket().CompletedAt.AsTime().Unix(),
		CanceledAtUnix:  res.GetTicket().CanceledAt.AsTime().Unix(),
	}

	result := &models.CreateTicketResponse{
		Ticket: ticket,
	}

	c.JSON(http.StatusCreated, result)
}

func (th *TicketHandler) GetTicket(c *gin.Context) {

	var req models.GetTicketRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	res, err := th.ticketClient.GetTicket(ctx, &ticketv1.GetTicketRequest{
		TicketId: req.TicketID,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	ticket := &models.Ticket{
		ID:              res.GetTicket().GetId(),
		DepartmentID:    res.GetTicket().GetDepartmentId(),
		CategoryID:      res.GetTicket().GetCategoryId(),
		UserID:          res.GetTicket().GetUserId(),
		BrigadeID:       res.GetTicket().GetBrigadeId(),
		Title:           res.GetTicket().GetTitle(),
		Description:     res.GetTicket().GetDescription(),
		Status:          string(res.GetTicket().GetStatus()),
		Priority:        string(res.GetTicket().GetPriority()),
		Address:         res.GetTicket().GetAddress(),
		Latitude:        res.GetTicket().GetLatitude(),
		Longitude:       res.GetTicket().GetLongitude(),
		CreatedAtUnix:   res.GetTicket().CreatedAt.AsTime().Unix(),
		UpdatedAtUnix:   res.GetTicket().UpdatedAt.AsTime().Unix(),
		AssignedAtUnix:  res.GetTicket().AssignedAt.AsTime().Unix(),
		CompletedAtUnix: res.GetTicket().CompletedAt.AsTime().Unix(),
		CanceledAtUnix:  res.GetTicket().CanceledAt.AsTime().Unix(),
	}

	result := &models.GetTicketResponse{
		Ticket: ticket,
	}

	c.JSON(http.StatusOK, result)
}

func (th *TicketHandler) ListTicket(c *gin.Context) {
	var req models.ListTicketRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	res, err := th.ticketClient.ListTickets(ctx, &ticketv1.ListTicketsRequest{
		DepartmentId: *req.DepartmentID,
		UserId:       *req.UserID,
		BrigadeId:    *req.BrigadeID,
		CategoryId:   *req.CategoryID,
		Status:       ToProtoStatus(*req.Status),
	})
}
