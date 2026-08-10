package service

import (
	"context"
	"testing"

	"routing/models"
)

type engineStub struct {
	cells []models.MatrixCell
	route *models.CalculatedRoute
}

func (s *engineStub) BuildRoute(
	context.Context,
	*models.BuildRouteInput,
) (*models.CalculatedRoute, error) {
	return s.route, nil
}

func (s *engineStub) BuildMatrix(
	context.Context,
	*models.BuildMatrixInput,
) ([]models.MatrixCell, error) {
	return s.cells, nil
}

type repoStub struct {
	route *models.Route
}

func (s *repoStub) CreateRoute(
	_ context.Context,
	route *models.Route,
) (*models.Route, error) {
	s.route = route
	return route, nil
}

func (s *repoStub) GetRoute(
	context.Context,
	string,
) (*models.Route, error) {
	return s.route, nil
}

func (s *repoStub) UpdateCalculation(
	_ context.Context,
	route *models.Route,
) (*models.Route, error) {
	s.route = route
	return route, nil
}

func (s *repoStub) UpdateStatus(
	_ context.Context,
	_ string,
	status models.RouteStatus,
) (*models.Route, error) {
	s.route.Status = status
	return s.route, nil
}

func (s *repoStub) ListRoutes(
	context.Context,
	*models.ListRoutesInput,
) (*models.ListRoutesResult, error) {
	return &models.ListRoutesResult{}, nil
}

func TestRankCandidatesOrdersByETA(t *testing.T) {
	engine := &engineStub{
		cells: []models.MatrixCell{
			{
				SourceIndex:     0,
				TargetIndex:     0,
				DurationSeconds: 120,
				DistanceMeters:  1000,
				Reachable:       true,
			},
			{
				SourceIndex:     1,
				TargetIndex:     0,
				DurationSeconds: 60,
				DistanceMeters:  2000,
				Reachable:       true,
			},
		},
	}
	value := New(&repoStub{}, engine, nil)
	result, err := value.RankCandidates(
		context.Background(),
		&models.RankCandidatesInput{
			Destination: models.Point{Latitude: 55.75, Longitude: 37.61},
			Candidates: []models.Candidate{
				{
					BrigadeID: "first",
					Location:  models.Point{Latitude: 55.70, Longitude: 37.60},
				},
				{
					BrigadeID: "second",
					Location:  models.Point{Latitude: 55.71, Longitude: 37.60},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("rank candidates: %v", err)
	}
	if result[0].BrigadeID != "second" || result[0].Rank != 1 {
		t.Fatalf("ranking = %#v", result)
	}
}

func TestCreateAndRecalculateRoute(t *testing.T) {
	calculated := &models.CalculatedRoute{
		Engine:  "valhalla",
		Summary: models.RouteSummary{DurationSeconds: 60},
	}
	repo := &repoStub{}
	value := New(
		repo,
		&engineStub{route: calculated},
		nil,
	)
	route, err := value.CreateRoute(
		context.Background(),
		&models.CreateRouteInput{
			TicketID:    "14c39ee8-0104-4b07-9a97-f0b62b35e844",
			BrigadeID:   "f28296a1-999c-4708-9e85-04984530e90d",
			Origin:      models.Point{Latitude: 55.75, Longitude: 37.61},
			Destination: models.Point{Latitude: 55.76, Longitude: 37.62},
		},
	)
	if err != nil {
		t.Fatalf("create route: %v", err)
	}
	updated, err := value.RecalculateRoute(
		context.Background(),
		&models.RecalculateRouteInput{
			ID: route.ID,
			CurrentPosition: models.Point{
				Latitude:  55.755,
				Longitude: 37.615,
			},
		},
	)
	if err != nil {
		t.Fatalf("recalculate route: %v", err)
	}
	if updated.Revision != 2 || updated.Origin.Latitude != 55.755 {
		t.Fatalf("updated route = %#v", updated)
	}
}
