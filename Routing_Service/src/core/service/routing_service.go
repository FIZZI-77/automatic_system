package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"routing/models"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Service struct {
	repo   RouteRepository
	engine RoutingEngine
	log    *zap.Logger
}

func New(
	repo RouteRepository,
	engine RoutingEngine,
	logger *zap.Logger,
) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{
		repo:   repo,
		engine: engine,
		log:    logger,
	}
}

func (s *Service) BuildRoute(
	ctx context.Context,
	in *models.BuildRouteInput,
) (*models.CalculatedRoute, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	in.Options = in.Options.Normalize()
	route, err := s.engine.BuildRoute(ctx, in)
	if err != nil {
		s.log.Warn("route calculation failed", zap.Error(err))
		return nil, err
	}
	return route, nil
}

func (s *Service) BuildMatrix(
	ctx context.Context,
	in *models.BuildMatrixInput,
) ([]models.MatrixCell, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	in.Options = in.Options.Normalize()
	return s.engine.BuildMatrix(ctx, in)
}

func (s *Service) RankCandidates(
	ctx context.Context,
	in *models.RankCandidatesInput,
) ([]models.RankedCandidate, error) {
	if in == nil || len(in.Candidates) == 0 {
		return nil, fmt.Errorf("%w: candidates", models.ErrInvalidArgument)
	}
	if err := in.Destination.Validate("destination"); err != nil {
		return nil, err
	}
	sources := make([]models.Point, 0, len(in.Candidates))
	for _, candidate := range in.Candidates {
		if strings.TrimSpace(candidate.BrigadeID) == "" {
			return nil, fmt.Errorf("%w: brigade id", models.ErrInvalidArgument)
		}
		if err := candidate.Location.Validate("candidate location"); err != nil {
			return nil, err
		}
		sources = append(sources, candidate.Location)
	}
	cells, err := s.BuildMatrix(ctx, &models.BuildMatrixInput{
		Sources: sources,
		Targets: []models.Point{in.Destination},
		Options: in.Options,
	})
	if err != nil {
		return nil, err
	}

	ranked := make([]models.RankedCandidate, 0, len(in.Candidates))
	for index, candidate := range in.Candidates {
		value := models.RankedCandidate{Candidate: candidate}
		for _, cell := range cells {
			if cell.SourceIndex == int32(index) && cell.TargetIndex == 0 {
				value.DistanceMeters = cell.DistanceMeters
				value.ETASeconds = cell.DurationSeconds
				value.Reachable = cell.Reachable
				break
			}
		}
		ranked = append(ranked, value)
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].Reachable != ranked[j].Reachable {
			return ranked[i].Reachable
		}
		if ranked[i].ETASeconds == ranked[j].ETASeconds {
			return ranked[i].DistanceMeters < ranked[j].DistanceMeters
		}
		return ranked[i].ETASeconds < ranked[j].ETASeconds
	})
	if in.Limit > 0 && int(in.Limit) < len(ranked) {
		ranked = ranked[:in.Limit]
	}
	for index := range ranked {
		ranked[index].Rank = int32(index + 1)
	}
	return ranked, nil
}

func (s *Service) CreateRoute(
	ctx context.Context,
	in *models.CreateRouteInput,
) (*models.Route, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	if lookup, ok := s.repo.(interface {
		GetOpenRouteByTicket(context.Context, string) (*models.Route, error)
	}); ok {
		if existing, err := lookup.GetOpenRouteByTicket(ctx, in.TicketID); err == nil {
			if existing.BrigadeID != in.BrigadeID {
				return nil, fmt.Errorf("%w: ticket already has an open route", models.ErrConflict)
			}
			return existing, nil
		} else if !errors.Is(err, models.ErrNotFound) {
			return nil, err
		}
	}
	options := in.Options.Normalize()
	calculation, err := s.BuildRoute(ctx, &models.BuildRouteInput{
		Origin:      in.Origin,
		Destination: in.Destination,
		Waypoints:   in.Waypoints,
		Options:     options,
	})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	route := &models.Route{
		ID:          uuid.NewString(),
		TicketID:    in.TicketID,
		BrigadeID:   in.BrigadeID,
		Status:      models.RouteStatusPlanned,
		Origin:      in.Origin,
		Destination: in.Destination,
		Waypoints:   append([]models.Point(nil), in.Waypoints...),
		Options:     options,
		Calculation: *calculation,
		Revision:    1,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	return s.repo.CreateRoute(ctx, route)
}

func (s *Service) GetRoute(
	ctx context.Context,
	id string,
) (*models.Route, error) {
	if _, err := uuid.Parse(strings.TrimSpace(id)); err != nil {
		return nil, fmt.Errorf("%w: route id", models.ErrInvalidArgument)
	}
	return s.repo.GetRoute(ctx, id)
}

func (s *Service) RecalculateRoute(
	ctx context.Context,
	in *models.RecalculateRouteInput,
) (*models.Route, error) {
	if in == nil {
		return nil, fmt.Errorf("%w: request", models.ErrInvalidArgument)
	}
	if err := in.CurrentPosition.Validate("current position"); err != nil {
		return nil, err
	}
	route, err := s.GetRoute(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	calculation, err := s.BuildRoute(ctx, &models.BuildRouteInput{
		Origin:      in.CurrentPosition,
		Destination: route.Destination,
		Waypoints:   route.Waypoints,
		Options:     route.Options,
	})
	if err != nil {
		return nil, err
	}
	route.Origin = in.CurrentPosition
	route.Calculation = *calculation
	route.Revision++
	route.UpdatedAt = time.Now().UTC()
	return s.repo.UpdateCalculation(ctx, route)
}

func (s *Service) ListRoutes(
	ctx context.Context,
	in *models.ListRoutesInput,
) (*models.ListRoutesResult, error) {
	if in == nil {
		in = &models.ListRoutesInput{}
	}
	if in.Limit <= 0 {
		in.Limit = 50
	}
	if in.Limit > 500 || in.Offset < 0 {
		return nil, fmt.Errorf("%w: pagination", models.ErrInvalidArgument)
	}
	return s.repo.ListRoutes(ctx, in)
}
