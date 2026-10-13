package handler

import (
	"context"
	"fmt"

	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/google/uuid"

	"ticket/models"
)

func (t *TicketHandler) CreateRequest(
	ctx context.Context,
	req *ticketv1.CreateRequestRequest,
) (*ticketv1.CreateRequestResponse, error) {
	actor := actorFromContext(ctx)

	if actor.UserID == nil {
		return nil, ticketStatusError("CreateRequest", models.ErrPermissionDenied)
	}

	departmentID, err := parseRequestUUID(req.GetDepartmentId(), "department_id")

	if err != nil {
		return nil, ticketStatusError("CreateRequest", err)
	}

	categoryID, err := parseRequestUUID(req.GetCategoryId(), "category_id")

	if err != nil {
		return nil, ticketStatusError("CreateRequest", err)
	}

	userID, err := parseRequestUUID(req.GetUserId(), "user_id")

	if err != nil {
		return nil, ticketStatusError("CreateRequest", err)
	}

	if userID != *actor.UserID && !containsRole(actor.Roles, "admin") && !containsRole(actor.Roles, "dispatcher") {
		return nil, ticketStatusError("CreateRequest", models.ErrPermissionDenied)
	}

	assetID, err := parseOptionalRequestUUID(req.AssetId, "asset_id")

	if err != nil {
		return nil, ticketStatusError("CreateRequest", err)
	}

	result, err := t.service.CreateRequest(ctx, &models.CreateRequestInput{
		DepartmentID: departmentID,
		CategoryID:   categoryID,
		UserID:       userID,
		Title:        req.GetTitle(),
		Description:  req.GetDescription(),
		Priority:     FromProtoPriority(req.GetPriority()),
		Address:      req.GetAddress(),
		Latitude:     req.GetLatitude(),
		Longitude:    req.GetLongitude(),
		AssetID:      assetID,
	})

	if err != nil {
		return nil, ticketStatusError("CreateRequest", err)
	}

	return &ticketv1.CreateRequestResponse{
		Request:          ToProtoTicket(result.Request),
		Incident:         ToProtoTicket(result.Incident),
		DuplicateMatched: result.DuplicateMatched,
	}, nil
}

func (t *TicketHandler) AttachRequest(
	ctx context.Context,
	req *ticketv1.AttachRequestRequest,
) (*ticketv1.AttachRequestResponse, error) {
	actor := actorFromContext(ctx)

	if actor.UserID == nil {
		return nil, ticketStatusError("AttachRequest", models.ErrPermissionDenied)
	}

	incidentID, err := parseRequestUUID(req.GetIncidentId(), "incident_id")

	if err != nil {
		return nil, ticketStatusError("AttachRequest", err)
	}

	requestID, err := parseRequestUUID(req.GetRequestId(), "request_id")

	if err != nil {
		return nil, ticketStatusError("AttachRequest", err)
	}

	request, err := t.service.AttachRequest(ctx, &models.AttachRequestInput{
		IncidentID:        incidentID,
		RequestID:         requestID,
		ChangedBy:         *actor.UserID,
		Reason:            req.GetReason(),
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
	})

	if err != nil {
		return nil, ticketStatusError("AttachRequest", err)
	}

	return &ticketv1.AttachRequestResponse{Request: ToProtoTicket(request)}, nil
}

func (t *TicketHandler) DetachRequest(
	ctx context.Context,
	req *ticketv1.DetachRequestRequest,
) (*ticketv1.DetachRequestResponse, error) {
	actor := actorFromContext(ctx)

	if actor.UserID == nil {
		return nil, ticketStatusError("DetachRequest", models.ErrPermissionDenied)
	}

	requestID, err := parseRequestUUID(req.GetRequestId(), "request_id")

	if err != nil {
		return nil, ticketStatusError("DetachRequest", err)
	}

	request, err := t.service.DetachRequest(ctx, &models.DetachRequestInput{
		RequestID:         requestID,
		ChangedBy:         *actor.UserID,
		Reason:            req.GetReason(),
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
	})

	if err != nil {
		return nil, ticketStatusError("DetachRequest", err)
	}

	return &ticketv1.DetachRequestResponse{Request: ToProtoTicket(request)}, nil
}

func (t *TicketHandler) ListIncidentRequests(
	ctx context.Context,
	req *ticketv1.ListIncidentRequestsRequest,
) (*ticketv1.ListIncidentRequestsResponse, error) {
	actor := actorFromContext(ctx)

	if actor.UserID == nil {
		return nil, ticketStatusError("ListIncidentRequests", models.ErrPermissionDenied)
	}

	incidentID, err := parseRequestUUID(req.GetIncidentId(), "incident_id")

	if err != nil {
		return nil, ticketStatusError("ListIncidentRequests", err)
	}

	requests, total, err := t.service.ListIncidentRequests(ctx, &models.ListIncidentRequestsInput{
		IncidentID:        incidentID,
		Limit:             req.GetLimit(),
		Offset:            req.GetOffset(),
		ActorDepartmentID: actor.DepartmentID,
		ActorRoles:        actor.Roles,
	})

	if err != nil {
		return nil, ticketStatusError("ListIncidentRequests", err)
	}

	response := make([]*ticketv1.Ticket, 0, len(requests))

	for _, request := range requests {
		response = append(response, ToProtoTicket(request))
	}

	return &ticketv1.ListIncidentRequestsResponse{
		Requests: response,
		Total:    total,
	}, nil
}

func (t *TicketHandler) RegisterIntegration(
	ctx context.Context,
	req *ticketv1.RegisterIntegrationRequest,
) (*ticketv1.RegisterIntegrationResponse, error) {
	actor := actorFromContext(ctx)

	if actor.UserID == nil {
		return nil, ticketStatusError("RegisterIntegration", models.ErrPermissionDenied)
	}

	allowedDepartmentID, err := parseOptionalRequestUUID(req.AllowedDepartmentId, "allowed_department_id")

	if err != nil {
		return nil, ticketStatusError("RegisterIntegration", err)
	}

	result, err := t.service.RegisterIntegration(ctx, &models.RegisterIntegrationInput{
		Name:                req.GetName(),
		ClientID:            req.GetClientId(),
		AllowedDepartmentID: allowedDepartmentID,
		CreatedBy:           *actor.UserID,
		ActorRoles:          actor.Roles,
	})

	if err != nil {
		return nil, ticketStatusError("RegisterIntegration", err)
	}

	return &ticketv1.RegisterIntegrationResponse{
		Integration: toProtoTicketIntegration(result.Integration),
		Secret:      result.Secret,
	}, nil
}

func (t *TicketHandler) CreateExternalRequest(
	ctx context.Context,
	req *ticketv1.CreateExternalRequestRequest,
) (*ticketv1.CreateExternalRequestResponse, error) {
	departmentID, err := parseRequestUUID(req.GetDepartmentId(), "department_id")

	if err != nil {
		return nil, ticketStatusError("CreateExternalRequest", err)
	}

	categoryID, err := parseRequestUUID(req.GetCategoryId(), "category_id")

	if err != nil {
		return nil, ticketStatusError("CreateExternalRequest", err)
	}

	userID, err := parseRequestUUID(req.GetUserId(), "user_id")

	if err != nil {
		return nil, ticketStatusError("CreateExternalRequest", err)
	}

	assetID, err := parseOptionalRequestUUID(req.AssetId, "asset_id")

	if err != nil {
		return nil, ticketStatusError("CreateExternalRequest", err)
	}

	result, err := t.service.CreateExternalRequest(ctx, &models.CreateExternalRequestInput{
		ClientID:   req.GetClientId(),
		Secret:     req.GetSecret(),
		ExternalID: req.GetExternalId(),
		Request: models.CreateRequestInput{
			DepartmentID: departmentID,
			CategoryID:   categoryID,
			UserID:       userID,
			Title:        req.GetTitle(),
			Description:  req.GetDescription(),
			Priority:     FromProtoPriority(req.GetPriority()),
			Address:      req.GetAddress(),
			Latitude:     req.GetLatitude(),
			Longitude:    req.GetLongitude(),
			AssetID:      assetID,
		},
	})

	if err != nil {
		return nil, ticketStatusError("CreateExternalRequest", err)
	}

	return &ticketv1.CreateExternalRequestResponse{
		Request:          ToProtoTicket(result.Request),
		Incident:         ToProtoTicket(result.Incident),
		DuplicateMatched: result.DuplicateMatched,
	}, nil
}

func parseRequestUUID(value string, field string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)

	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: invalid %s", models.ErrValidation, field)
	}

	return parsed, nil
}

func parseOptionalRequestUUID(value *string, field string) (*uuid.UUID, error) {

	if value == nil || *value == "" {
		return nil, nil
	}

	parsed, err := parseRequestUUID(*value, field)

	if err != nil {
		return nil, err
	}

	return &parsed, nil
}

func toProtoTicketIntegration(integration *models.TicketIntegration) *ticketv1.TicketIntegration {

	if integration == nil {
		return nil
	}

	return &ticketv1.TicketIntegration{
		Id:                  integration.ID.String(),
		Name:                integration.Name,
		ClientId:            integration.ClientID,
		SecretPrefix:        integration.SecretPrefix,
		AllowedDepartmentId: uuidStringPtr(integration.AllowedDepartmentID),
		IsActive:            integration.IsActive,
		CreatedBy:           integration.CreatedBy.String(),
		CreatedAt:           ToProtoTimestamp(integration.CreatedAt),
		UpdatedAt:           ToProtoTimestamp(integration.UpdatedAt),
		LastUsedAt:          ToProtoTimestampPtr(integration.LastUsedAt),
	}
}
