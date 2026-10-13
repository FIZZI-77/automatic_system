package handlers

import (
	"context"
	"net/http"
	"time"

	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gateway/models"
)

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

	requests := make([]*models.Ticket, 0, len(response.GetRequests()))

	for _, request := range response.GetRequests() {
		requests = append(requests, FromProtoTicket(request))
	}

	c.JSON(http.StatusOK, &models.ListIncidentRequestsResponse{
		Requests: requests,
		Total:    response.GetTotal(),
	})
}

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

func timestampTime(value *timestamppb.Timestamp) time.Time {

	if value == nil {
		return time.Time{}
	}

	return value.AsTime()
}
