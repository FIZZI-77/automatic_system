package handler

import (
	"context"
	"strings"

	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"routing/models"
)

// actorOutgoing переносит входящие метаданные в исходящий контекст вызова Ticket.
func actorOutgoing(ctx context.Context) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	return metadata.NewOutgoingContext(ctx, md.Copy())
}

// actorRole проверяет наличие ожидаемой роли в метаданных входящего gRPC-запроса.
func actorRole(ctx context.Context, expected string) bool {
	md, _ := metadata.FromIncomingContext(ctx)
	for _, value := range md.Get("x-actor-roles") {
		for _, role := range strings.Split(value, ",") {
			if strings.TrimSpace(role) == expected {
				return true
			}
		}
	}
	return false
}

// requireActor проверяет наличие корректного идентификатора пользователя-актора.
func requireActor(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("x-actor-user-id")
	if len(values) != 1 {
		return status.Error(codes.Unauthenticated, "actor required")
	}
	id, err := uuid.Parse(values[0])
	if err != nil || id == uuid.Nil {
		return status.Error(codes.Unauthenticated, "invalid actor")
	}
	return nil
}

// authorizeTicket проверяет права актора на билет и возвращает сам билет.
func (h *Handler) authorizeTicket(ctx context.Context, id string, write bool) (*ticketv1.Ticket, error) {
	if err := requireActor(ctx); err != nil {
		return nil, err
	}
	if write && !actorRole(ctx, "admin") && !actorRole(ctx, "dispatcher") {
		return nil, status.Error(codes.PermissionDenied, "route management requires dispatcher")
	}
	if h.tickets == nil {
		return nil, status.Error(codes.Unavailable, "ticket authorization unavailable")
	}
	result, err := h.tickets.GetTicket(actorOutgoing(ctx), &ticketv1.GetTicketRequest{TicketId: id})
	if err != nil {
		return nil, err
	}
	if result.GetTicket() == nil {
		return nil, status.Error(codes.PermissionDenied, "ticket access denied")
	}
	return result.GetTicket(), nil
}

// authorizeRoute проверяет права актора на маршрут через связанный билет.
func (h *Handler) authorizeRoute(ctx context.Context, id string, write bool) (*models.Route, error) {
	if err := requireActor(ctx); err != nil {
		return nil, err
	}
	route, err := h.service.GetRoute(ctx, id)
	if err != nil {
		return nil, mapError(err)
	}
	if _, err := h.authorizeTicket(ctx, route.TicketID, write); err != nil {
		return nil, err
	}
	return route, nil
}

// allowedTickets delegates ownership rules to Ticket before route count/pagination.
// A nil slice is reserved for admins; an empty non-nil slice allows no tickets.
func (h *Handler) allowedTickets(ctx context.Context, ticketID *string) ([]string, error) {
	if err := requireActor(ctx); err != nil {
		return nil, err
	}
	if ticketID != nil {
		if _, err := h.authorizeTicket(ctx, *ticketID, false); err != nil {
			return nil, err
		}
		return []string{*ticketID}, nil
	}
	if actorRole(ctx, "admin") {
		return nil, nil
	}
	if h.tickets == nil {
		return nil, status.Error(codes.Unavailable, "ticket authorization unavailable")
	}
	allowed := make([]string, 0)
	const pageSize int32 = 100
	for page := int32(0); page < 100; page++ {
		result, err := h.tickets.ListTickets(actorOutgoing(ctx), &ticketv1.ListTicketsRequest{Limit: pageSize, Offset: page * pageSize})
		if err != nil {
			return nil, err
		}
		for _, ticket := range result.GetTickets() {
			allowed = append(allowed, ticket.GetId())
		}
		if len(result.GetTickets()) < int(pageSize) || (result.GetTotal() > 0 && int64(len(allowed)) >= result.GetTotal()) {
			return allowed, nil
		}
	}
	return nil, status.Error(codes.ResourceExhausted, "specify ticket_id to narrow route listing")
}
