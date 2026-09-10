package service

import (
	"context"

	"routing/models"
)

type RoutingEngine interface {
	BuildRoute(
		ctx context.Context,
		in *models.BuildRouteInput,
	) (*models.CalculatedRoute, error)
	BuildMatrix(
		ctx context.Context,
		in *models.BuildMatrixInput,
	) ([]models.MatrixCell, error)
}

type RouteRepository interface {
	CreateRoute(
		ctx context.Context,
		route *models.Route,
	) (*models.Route, error)
	GetRoute(ctx context.Context, id string) (*models.Route, error)
	UpdateCalculation(
		ctx context.Context,
		route *models.Route,
	) (*models.Route, error)
	UpdateStatus(
		ctx context.Context,
		id string,
		status models.RouteStatus,
	) (*models.Route, error)
	ListRoutes(
		ctx context.Context,
		in *models.ListRoutesInput,
	) (*models.ListRoutesResult, error)
}

type RoutingService interface {
	BuildRoute(
		ctx context.Context,
		in *models.BuildRouteInput,
	) (*models.CalculatedRoute, error)
	BuildMatrix(
		ctx context.Context,
		in *models.BuildMatrixInput,
	) ([]models.MatrixCell, error)
	RankCandidates(
		ctx context.Context,
		in *models.RankCandidatesInput,
	) ([]models.RankedCandidate, error)
	CreateRoute(
		ctx context.Context,
		in *models.CreateRouteInput,
	) (*models.Route, error)
	GetRoute(ctx context.Context, id string) (*models.Route, error)
	RecalculateRoute(
		ctx context.Context,
		in *models.RecalculateRouteInput,
	) (*models.Route, error)
	SetRouteStatus(
		ctx context.Context,
		id string,
		status models.RouteStatus,
	) (*models.Route, error)
	ListRoutes(
		ctx context.Context,
		in *models.ListRoutesInput,
	) (*models.ListRoutesResult, error)
}
