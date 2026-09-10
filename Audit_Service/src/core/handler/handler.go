package handler

import (
	"context"
	"strings"

	"audit/models"
	"audit/src/core/service"
	auditv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/audit/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Handler struct {
	auditv1.UnimplementedAuditServiceServer
	service service.AuditService
}

func New(service service.AuditService) *Handler {
	return &Handler{service: service}
}

func (h *Handler) GetAuditEntry(ctx context.Context, req *auditv1.GetAuditEntryRequest) (*auditv1.GetAuditEntryResponse, error) {
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid audit entry id")
	}
	entry, err := h.service.Get(ctx, id)
	if err != nil {
		return nil, mapError(err)
	}
	return &auditv1.GetAuditEntryResponse{Entry: toProto(entry)}, nil
}

func (h *Handler) ListAuditEntries(ctx context.Context, req *auditv1.ListAuditEntriesRequest) (*auditv1.ListAuditEntriesResponse, error) {
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	filter := models.Filter{
		Action:     req.Action,
		EntityType: req.EntityType,
		EntityID:   req.EntityId,
		RequestID:  req.RequestId,
		TraceID:    req.TraceId,
		Topic:      req.Topic,
		Limit:      req.GetLimit(),
		Offset:     req.GetOffset(),
	}
	if req.ActorId != nil {
		id, err := uuid.Parse(req.GetActorId())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid actor id")
		}
		filter.ActorID = &id
	}
	if req.From != nil {
		value := req.From.AsTime()
		filter.From = &value
	}
	if req.To != nil {
		value := req.To.AsTime()
		filter.To = &value
	}
	entries, total, err := h.service.List(ctx, filter)
	if err != nil {
		return nil, mapError(err)
	}
	result := make([]*auditv1.AuditEntry, 0, len(entries))
	for _, entry := range entries {
		result = append(result, toProto(entry))
	}
	return &auditv1.ListAuditEntriesResponse{Entries: result, Total: total}, nil
}

func authorize(ctx context.Context) error {
	values, _ := metadata.FromIncomingContext(ctx)
	roles := strings.Split(strings.Join(values.Get("x-actor-roles"), ","), ",")
	for _, role := range roles {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "admin", "dispatcher":
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "admin or dispatcher role required")
}

func toProto(entry *models.Entry) *auditv1.AuditEntry {
	if entry == nil {
		return nil
	}
	data, _ := structpb.NewStruct(entry.Data)
	result := &auditv1.AuditEntry{
		Id:         entry.ID.String(),
		EventId:    entry.EventID,
		Topic:      entry.Topic,
		Action:     entry.Action,
		EntityType: entry.EntityType,
		EntityId:   entry.EntityID,
		RequestId:  entry.RequestID,
		TraceId:    entry.TraceID,
		Data:       data,
		OccurredAt: timestamppb.New(entry.OccurredAt),
		RecordedAt: timestamppb.New(entry.RecordedAt),
	}
	if entry.ActorID != nil {
		value := entry.ActorID.String()
		result.ActorId = &value
	}
	return result
}

func mapError(err error) error {
	if service.IsNotFound(err) {
		return status.Error(codes.NotFound, "audit entry not found")
	}
	return status.Error(codes.Internal, "audit operation failed")
}
