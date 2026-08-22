package handler

import (
	"context"
	"errors"
	"strings"
	"time"

	"dispatch/models"
	"dispatch/src/core/service"

	dispatchv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/dispatch/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Handler struct {
	dispatchv1.UnimplementedDispatchServiceServer
	service *service.Service
}

func New(value *service.Service) *Handler { return &Handler{service: value} }

func (h *Handler) PreviewDispatch(ctx context.Context, req *dispatchv1.PreviewDispatchRequest) (*dispatchv1.PreviewDispatchResponse, error) {
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	ticketID, skills, err := parseInputIDs(req.GetTicketId(), req.GetRequiredSkillIds())
	if err != nil {
		return nil, err
	}
	items, err := h.service.Preview(ctx, &models.RecommendInput{TicketID: ticketID, RequiredSkillIDs: skills, Limit: req.GetLimit()})
	if err != nil {
		return nil, mapError(err)
	}
	result := make([]*dispatchv1.DispatchCandidate, 0, len(items))
	for _, item := range items {
		result = append(result, &dispatchv1.DispatchCandidate{BrigadeId: item.BrigadeID.String(), Rank: item.Rank, DistanceMeters: item.DistanceMeters, EtaSeconds: item.ETASeconds, Reachable: item.Reachable, Latitude: item.Latitude, Longitude: item.Longitude})
	}
	return &dispatchv1.PreviewDispatchResponse{Candidates: result}, nil
}

func (h *Handler) ReserveBrigade(ctx context.Context, req *dispatchv1.ReserveBrigadeRequest) (*dispatchv1.ReserveBrigadeResponse, error) {
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	ticketID, skills, err := parseInputIDs(req.GetTicketId(), req.GetRequiredSkillIds())
	if err != nil {
		return nil, err
	}
	brigadeID, err := parseID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, err
	}
	actor, err := parseID(req.GetRequestedBy(), "requested_by")
	if err != nil {
		return nil, err
	}
	var ttl time.Duration
	if req.ReservationTtlSeconds != nil {
		ttl = time.Duration(req.GetReservationTtlSeconds()) * time.Second
	}
	op, err := h.service.Reserve(ctx, &models.ReserveInput{TicketID: ticketID, BrigadeID: brigadeID, RequiredSkillIDs: skills, RequestedBy: actor, TTL: ttl})
	if err != nil {
		return nil, mapError(err)
	}
	return &dispatchv1.ReserveBrigadeResponse{Operation: toProto(op)}, nil
}

func (h *Handler) ConfirmDispatch(ctx context.Context, req *dispatchv1.ConfirmDispatchRequest) (*dispatchv1.ConfirmDispatchResponse, error) {
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	id, err := parseID(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	actor, err := parseID(req.GetConfirmedBy(), "confirmed_by")
	if err != nil {
		return nil, err
	}
	op, err := h.service.Confirm(ctx, &models.ConfirmInput{ID: id, ConfirmedBy: actor, ExpectedVersion: req.GetExpectedVersion()})
	if err != nil {
		return nil, mapError(err)
	}
	return &dispatchv1.ConfirmDispatchResponse{Operation: toProto(op)}, nil
}

func (h *Handler) AutoDispatch(ctx context.Context, req *dispatchv1.AutoDispatchRequest) (*dispatchv1.AutoDispatchResponse, error) {
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	ticketID, skills, err := parseInputIDs(req.GetTicketId(), req.GetRequiredSkillIds())
	if err != nil {
		return nil, err
	}
	actor, err := parseID(req.GetRequestedBy(), "requested_by")
	if err != nil {
		return nil, err
	}
	op, err := h.service.AutoDispatch(ctx, &models.AutoInput{TicketID: ticketID, RequiredSkillIDs: skills, RequestedBy: actor, CandidateLimit: req.GetCandidateLimit()})
	if err != nil {
		return nil, mapError(err)
	}
	return &dispatchv1.AutoDispatchResponse{Operation: toProto(op)}, nil
}

func (h *Handler) GetDispatch(ctx context.Context, req *dispatchv1.GetDispatchRequest) (*dispatchv1.GetDispatchResponse, error) {
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	id, err := parseID(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	op, err := h.service.Get(ctx, id)
	if err != nil {
		return nil, mapError(err)
	}
	return &dispatchv1.GetDispatchResponse{Operation: toProto(op)}, nil
}

func (h *Handler) ListDispatches(ctx context.Context, req *dispatchv1.ListDispatchesRequest) (*dispatchv1.ListDispatchesResponse, error) {
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	in := &models.ListInput{Limit: req.GetLimit(), Offset: req.GetOffset()}
	if req.TicketId != nil {
		value, err := parseID(req.GetTicketId(), "ticket_id")
		if err != nil {
			return nil, err
		}
		in.TicketID = &value
	}
	if req.BrigadeId != nil {
		value, err := parseID(req.GetBrigadeId(), "brigade_id")
		if err != nil {
			return nil, err
		}
		in.BrigadeID = &value
	}
	if req.Status != nil {
		value, ok := statusFromProto(req.GetStatus())
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "invalid status")
		}
		in.Status = &value
	}
	items, total, err := h.service.List(ctx, in)
	if err != nil {
		return nil, mapError(err)
	}
	result := make([]*dispatchv1.DispatchOperation, 0, len(items))
	for _, item := range items {
		result = append(result, toProto(item))
	}
	return &dispatchv1.ListDispatchesResponse{Operations: result, Total: total}, nil
}

func (h *Handler) CancelDispatch(ctx context.Context, req *dispatchv1.CancelDispatchRequest) (*dispatchv1.CancelDispatchResponse, error) {
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	id, err := parseID(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	actor, err := parseID(req.GetCancelledBy(), "cancelled_by")
	if err != nil {
		return nil, err
	}
	op, err := h.service.Cancel(ctx, &models.CancelInput{ID: id, CancelledBy: actor, ExpectedVersion: req.GetExpectedVersion(), Reason: req.GetReason()})
	if err != nil {
		return nil, mapError(err)
	}
	return &dispatchv1.CancelDispatchResponse{Operation: toProto(op)}, nil
}

func authorize(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	for _, value := range md.Get("x-actor-roles") {
		for _, role := range strings.Split(value, ",") {
			role = strings.TrimSpace(strings.ToLower(role))
			if role == "admin" || role == "dispatcher" {
				return nil
			}
		}
	}
	return status.Error(codes.PermissionDenied, "dispatcher or admin role required")
}

func parseID(raw, field string) (uuid.UUID, error) {
	value, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, status.Error(codes.InvalidArgument, "invalid "+field)
	}
	return value, nil
}
func parseInputIDs(ticket string, rawSkills []string) (uuid.UUID, []uuid.UUID, error) {
	ticketID, err := parseID(ticket, "ticket_id")
	if err != nil {
		return uuid.Nil, nil, err
	}
	skills := make([]uuid.UUID, 0, len(rawSkills))
	for _, raw := range rawSkills {
		value, parseErr := parseID(raw, "skill id")
		if parseErr != nil {
			return uuid.Nil, nil, parseErr
		}
		skills = append(skills, value)
	}
	return ticketID, skills, nil
}

func toProto(value *models.Operation) *dispatchv1.DispatchOperation {
	if value == nil {
		return nil
	}
	result := &dispatchv1.DispatchOperation{Id: value.ID.String(), TicketId: value.TicketID.String(), Mode: modeToProto(value.Mode), Status: statusToProto(value.Status), Version: value.Version, RequestedBy: value.RequestedBy.String(), ExpiresAtUnixMs: value.ExpiresAt.UnixMilli(), CreatedAtUnixMs: value.CreatedAt.UnixMilli(), UpdatedAtUnixMs: value.UpdatedAt.UnixMilli()}
	if value.BrigadeID != nil {
		result.BrigadeId = value.BrigadeID.String()
	}
	if value.RouteID != nil {
		result.RouteId = value.RouteID.String()
	}
	if value.FailureReason != nil {
		result.FailureReason = *value.FailureReason
	}
	return result
}
func modeToProto(value models.Mode) dispatchv1.DispatchMode {
	if value == models.ModeManual {
		return dispatchv1.DispatchMode_DISPATCH_MODE_MANUAL
	}
	if value == models.ModeAutomatic {
		return dispatchv1.DispatchMode_DISPATCH_MODE_AUTOMATIC
	}
	return dispatchv1.DispatchMode_DISPATCH_MODE_UNSPECIFIED
}
func statusToProto(value models.Status) dispatchv1.DispatchStatus {
	switch value {
	case models.StatusPending:
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_PENDING
	case models.StatusReserved:
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_RESERVED
	case models.StatusConfirming:
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_CONFIRMING
	case models.StatusAssigned:
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_ASSIGNED
	case models.StatusFailed:
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_FAILED
	case models.StatusCancelled:
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_CANCELLED
	case models.StatusExpired:
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_EXPIRED
	}
	return dispatchv1.DispatchStatus_DISPATCH_STATUS_UNSPECIFIED
}
func statusFromProto(value dispatchv1.DispatchStatus) (models.Status, bool) {
	switch value {
	case dispatchv1.DispatchStatus_DISPATCH_STATUS_PENDING:
		return models.StatusPending, true
	case dispatchv1.DispatchStatus_DISPATCH_STATUS_RESERVED:
		return models.StatusReserved, true
	case dispatchv1.DispatchStatus_DISPATCH_STATUS_CONFIRMING:
		return models.StatusConfirming, true
	case dispatchv1.DispatchStatus_DISPATCH_STATUS_ASSIGNED:
		return models.StatusAssigned, true
	case dispatchv1.DispatchStatus_DISPATCH_STATUS_FAILED:
		return models.StatusFailed, true
	case dispatchv1.DispatchStatus_DISPATCH_STATUS_CANCELLED:
		return models.StatusCancelled, true
	case dispatchv1.DispatchStatus_DISPATCH_STATUS_EXPIRED:
		return models.StatusExpired, true
	}
	return "", false
}
func mapError(err error) error {
	switch {
	case errors.Is(err, models.ErrInvalidArgument):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, models.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, models.ErrConflict):
		return status.Error(codes.Aborted, err.Error())
	case errors.Is(err, models.ErrForbidden):
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		return status.Error(codes.Unavailable, err.Error())
	}
}
