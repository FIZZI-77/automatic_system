package service

import (
	"context"
	"fmt"
	"strings"

	"routing/models"

	"github.com/google/uuid"
)

func (s *Service) SetRouteStatus(
	ctx context.Context,
	id string,
	target models.RouteStatus,
) (*models.Route, error) {
	if _, err := uuid.Parse(strings.TrimSpace(id)); err != nil {
		return nil, fmt.Errorf("%w: route id", models.ErrInvalidArgument)
	}
	route, err := s.repo.GetRoute(ctx, id)
	if err != nil {
		return nil, err
	}
	if !canTransition(route.Status, target) {
		return nil, fmt.Errorf(
			"%w: route status transition %s -> %s",
			models.ErrConflict,
			route.Status,
			target,
		)
	}
	return s.repo.UpdateStatus(ctx, id, target)
}

func canTransition(
	current models.RouteStatus,
	target models.RouteStatus,
) bool {
	switch current {
	case models.RouteStatusPlanned:
		return target == models.RouteStatusActive ||
			target == models.RouteStatusCancelled
	case models.RouteStatusActive:
		return target == models.RouteStatusCompleted ||
			target == models.RouteStatusCancelled
	default:
		return false
	}
}
