package service

import (
	"context"

	"ticket/models"

	"github.com/google/uuid"
)

type RouteReservation struct {
	RouteID string
	Created bool
}

type AssignmentRouteCreator interface {
	CreateForAssignment(ctx context.Context, ticket *models.Ticket, brigadeID uuid.UUID) (*RouteReservation, error)
	Cancel(ctx context.Context, routeID string) error
}
