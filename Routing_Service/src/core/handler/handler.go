package handler

import (
	"context"
	"errors"

	"routing/models"
	"routing/src/core/service"

	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Handler struct {
	routingv1.UnimplementedRoutingServiceServer
	service service.RoutingService
}

func New(value service.RoutingService) *Handler {
	return &Handler{service: value}
}

func (h *Handler) BuildRoute(
	ctx context.Context,
	request *routingv1.BuildRouteRequest,
) (*routingv1.BuildRouteResponse, error) {
	route, err := h.service.BuildRoute(ctx, buildRouteInput(request))
	if err != nil {
		return nil, mapError(err)
	}
	return &routingv1.BuildRouteResponse{
		Route: calculatedRouteToProto(route),
	}, nil
}

func (h *Handler) BuildMatrix(
	ctx context.Context,
	request *routingv1.BuildMatrixRequest,
) (*routingv1.BuildMatrixResponse, error) {
	cells, err := h.service.BuildMatrix(ctx, &models.BuildMatrixInput{
		Sources: pointsFromProto(request.GetSources()),
		Targets: pointsFromProto(request.GetTargets()),
		Options: optionsFromProto(request.GetOptions()),
	})
	if err != nil {
		return nil, mapError(err)
	}
	result := make([]*routingv1.MatrixCell, 0, len(cells))
	for _, cell := range cells {
		result = append(result, &routingv1.MatrixCell{
			SourceIndex:     cell.SourceIndex,
			TargetIndex:     cell.TargetIndex,
			DistanceMeters:  cell.DistanceMeters,
			DurationSeconds: cell.DurationSeconds,
			Reachable:       cell.Reachable,
		})
	}
	return &routingv1.BuildMatrixResponse{Cells: result}, nil
}

func (h *Handler) RankCandidates(
	ctx context.Context,
	request *routingv1.RankCandidatesRequest,
) (*routingv1.RankCandidatesResponse, error) {
	candidates := make([]models.Candidate, 0, len(request.GetCandidates()))
	for _, candidate := range request.GetCandidates() {
		candidates = append(candidates, models.Candidate{
			BrigadeID: candidate.GetBrigadeId(),
			Location:  pointFromProto(candidate.GetLocation()),
		})
	}
	ranked, err := h.service.RankCandidates(ctx, &models.RankCandidatesInput{
		Destination: pointFromProto(request.GetDestination()),
		Candidates:  candidates,
		Options:     optionsFromProto(request.GetOptions()),
		Limit:       request.GetLimit(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	result := make([]*routingv1.RankedCandidate, 0, len(ranked))
	for _, candidate := range ranked {
		result = append(result, &routingv1.RankedCandidate{
			BrigadeId:      candidate.BrigadeID,
			Location:       pointToProto(candidate.Location),
			Rank:           candidate.Rank,
			DistanceMeters: candidate.DistanceMeters,
			EtaSeconds:     candidate.ETASeconds,
			Reachable:      candidate.Reachable,
		})
	}
	return &routingv1.RankCandidatesResponse{Candidates: result}, nil
}

func (h *Handler) CreateRoute(
	ctx context.Context,
	request *routingv1.CreateRouteRequest,
) (*routingv1.CreateRouteResponse, error) {
	route, err := h.service.CreateRoute(ctx, &models.CreateRouteInput{
		TicketID:    request.GetTicketId(),
		BrigadeID:   request.GetBrigadeId(),
		Origin:      pointFromProto(request.GetOrigin()),
		Destination: pointFromProto(request.GetDestination()),
		Waypoints:   pointsFromProto(request.GetWaypoints()),
		Options:     optionsFromProto(request.GetOptions()),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &routingv1.CreateRouteResponse{Route: routeToProto(route)}, nil
}

func (h *Handler) GetRoute(
	ctx context.Context,
	request *routingv1.GetRouteRequest,
) (*routingv1.GetRouteResponse, error) {
	route, err := h.service.GetRoute(ctx, request.GetId())
	if err != nil {
		return nil, mapError(err)
	}
	return &routingv1.GetRouteResponse{Route: routeToProto(route)}, nil
}

func (h *Handler) RecalculateRoute(
	ctx context.Context,
	request *routingv1.RecalculateRouteRequest,
) (*routingv1.RecalculateRouteResponse, error) {
	route, err := h.service.RecalculateRoute(ctx, &models.RecalculateRouteInput{
		ID:              request.GetId(),
		CurrentPosition: pointFromProto(request.GetCurrentPosition()),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &routingv1.RecalculateRouteResponse{Route: routeToProto(route)}, nil
}

func (h *Handler) SetRouteStatus(
	ctx context.Context,
	request *routingv1.SetRouteStatusRequest,
) (*routingv1.SetRouteStatusResponse, error) {
	route, err := h.service.SetRouteStatus(
		ctx,
		request.GetId(),
		statusFromProto(request.GetStatus()),
	)
	if err != nil {
		return nil, mapError(err)
	}
	return &routingv1.SetRouteStatusResponse{
		Route: routeToProto(route),
	}, nil
}

func (h *Handler) ListRoutes(
	ctx context.Context,
	request *routingv1.ListRoutesRequest,
) (*routingv1.ListRoutesResponse, error) {
	input := &models.ListRoutesInput{
		TicketID:  request.TicketId,
		BrigadeID: request.BrigadeId,
		Limit:     request.GetLimit(),
		Offset:    request.GetOffset(),
	}
	if request.Status != nil {
		value := statusFromProto(request.GetStatus())
		input.Status = &value
	}
	result, err := h.service.ListRoutes(ctx, input)
	if err != nil {
		return nil, mapError(err)
	}
	routes := make([]*routingv1.Route, 0, len(result.Routes))
	for _, route := range result.Routes {
		routes = append(routes, routeToProto(route))
	}
	return &routingv1.ListRoutesResponse{
		Routes: routes,
		Total:  result.Total,
	}, nil
}

func buildRouteInput(request *routingv1.BuildRouteRequest) *models.BuildRouteInput {
	return &models.BuildRouteInput{
		Origin:      pointFromProto(request.GetOrigin()),
		Destination: pointFromProto(request.GetDestination()),
		Waypoints:   pointsFromProto(request.GetWaypoints()),
		Options:     optionsFromProto(request.GetOptions()),
	}
}

func pointFromProto(point *routingv1.Point) models.Point {
	if point == nil {
		return models.Point{}
	}
	return models.Point{
		Latitude:  point.GetLatitude(),
		Longitude: point.GetLongitude(),
	}
}

func pointToProto(point models.Point) *routingv1.Point {
	return &routingv1.Point{
		Latitude:  point.Latitude,
		Longitude: point.Longitude,
	}
}

func pointsFromProto(points []*routingv1.Point) []models.Point {
	result := make([]models.Point, 0, len(points))
	for _, point := range points {
		result = append(result, pointFromProto(point))
	}
	return result
}

func optionsFromProto(options *routingv1.RouteOptions) models.RouteOptions {
	if options == nil {
		return models.RouteOptions{}
	}
	result := models.RouteOptions{
		TravelMode:   modeFromProto(options.GetTravelMode()),
		Alternatives: options.GetAlternatives(),
	}
	if options.DepartureAt != nil {
		value := options.DepartureAt.AsTime()
		result.DepartureAt = &value
	}
	if options.Vehicle != nil {
		result.Vehicle = &models.VehicleConstraints{
			HeightMeters:       options.Vehicle.HeightMeters,
			WidthMeters:        options.Vehicle.WidthMeters,
			LengthMeters:       options.Vehicle.LengthMeters,
			WeightTons:         options.Vehicle.WeightTons,
			AxleLoadTons:       options.Vehicle.AxleLoadTons,
			HazardousMaterials: options.Vehicle.GetHazardousMaterials(),
		}
	}
	return result
}

func optionsToProto(options models.RouteOptions) *routingv1.RouteOptions {
	result := &routingv1.RouteOptions{
		TravelMode:   modeToProto(options.TravelMode),
		Alternatives: options.Alternatives,
	}
	if options.DepartureAt != nil {
		result.DepartureAt = timestamppb.New(*options.DepartureAt)
	}
	if options.Vehicle != nil {
		result.Vehicle = &routingv1.VehicleConstraints{
			HeightMeters:       options.Vehicle.HeightMeters,
			WidthMeters:        options.Vehicle.WidthMeters,
			LengthMeters:       options.Vehicle.LengthMeters,
			WeightTons:         options.Vehicle.WeightTons,
			AxleLoadTons:       options.Vehicle.AxleLoadTons,
			HazardousMaterials: options.Vehicle.HazardousMaterials,
		}
	}
	return result
}

func calculatedRouteToProto(route *models.CalculatedRoute) *routingv1.CalculatedRoute {
	if route == nil {
		return nil
	}
	legs := make([]*routingv1.RouteLeg, 0, len(route.Legs))
	for _, leg := range route.Legs {
		legs = append(legs, &routingv1.RouteLeg{
			From:            pointToProto(leg.From),
			To:              pointToProto(leg.To),
			DistanceMeters:  leg.DistanceMeters,
			DurationSeconds: leg.DurationSeconds,
		})
	}
	snapped := make([]*routingv1.Point, 0, len(route.SnappedPoints))
	for _, point := range route.SnappedPoints {
		snapped = append(snapped, pointToProto(point))
	}
	return &routingv1.CalculatedRoute{
		Summary: &routingv1.RouteSummary{
			DistanceMeters:  route.Summary.DistanceMeters,
			DurationSeconds: route.Summary.DurationSeconds,
		},
		EncodedPolyline: route.EncodedPolyline,
		Legs:            legs,
		SnappedPoints:   snapped,
		Engine:          route.Engine,
	}
}

func routeToProto(route *models.Route) *routingv1.Route {
	if route == nil {
		return nil
	}
	waypoints := make([]*routingv1.Point, 0, len(route.Waypoints))
	for _, point := range route.Waypoints {
		waypoints = append(waypoints, pointToProto(point))
	}
	return &routingv1.Route{
		Id:          route.ID,
		TicketId:    route.TicketID,
		BrigadeId:   route.BrigadeID,
		Status:      statusToProto(route.Status),
		Origin:      pointToProto(route.Origin),
		Destination: pointToProto(route.Destination),
		Waypoints:   waypoints,
		Options:     optionsToProto(route.Options),
		Calculation: calculatedRouteToProto(&route.Calculation),
		Revision:    route.Revision,
		CreatedAt:   timestamppb.New(route.CreatedAt),
		UpdatedAt:   timestamppb.New(route.UpdatedAt),
	}
}

func modeFromProto(value routingv1.TravelMode) models.TravelMode {
	switch value {
	case routingv1.TravelMode_TRAVEL_MODE_TRUCK:
		return models.TravelModeTruck
	case routingv1.TravelMode_TRAVEL_MODE_BICYCLE:
		return models.TravelModeBicycle
	case routingv1.TravelMode_TRAVEL_MODE_PEDESTRIAN:
		return models.TravelModePedestrian
	default:
		return models.TravelModeAuto
	}
}

func modeToProto(value models.TravelMode) routingv1.TravelMode {
	switch value {
	case models.TravelModeTruck:
		return routingv1.TravelMode_TRAVEL_MODE_TRUCK
	case models.TravelModeBicycle:
		return routingv1.TravelMode_TRAVEL_MODE_BICYCLE
	case models.TravelModePedestrian:
		return routingv1.TravelMode_TRAVEL_MODE_PEDESTRIAN
	default:
		return routingv1.TravelMode_TRAVEL_MODE_AUTO
	}
}

func statusFromProto(value routingv1.RouteStatus) models.RouteStatus {
	switch value {
	case routingv1.RouteStatus_ROUTE_STATUS_ACTIVE:
		return models.RouteStatusActive
	case routingv1.RouteStatus_ROUTE_STATUS_COMPLETED:
		return models.RouteStatusCompleted
	case routingv1.RouteStatus_ROUTE_STATUS_CANCELLED:
		return models.RouteStatusCancelled
	default:
		return models.RouteStatusPlanned
	}
}

func statusToProto(value models.RouteStatus) routingv1.RouteStatus {
	switch value {
	case models.RouteStatusActive:
		return routingv1.RouteStatus_ROUTE_STATUS_ACTIVE
	case models.RouteStatusCompleted:
		return routingv1.RouteStatus_ROUTE_STATUS_COMPLETED
	case models.RouteStatusCancelled:
		return routingv1.RouteStatus_ROUTE_STATUS_CANCELLED
	default:
		return routingv1.RouteStatus_ROUTE_STATUS_PLANNED
	}
}

func mapError(err error) error {
	switch {
	case errors.Is(err, models.ErrInvalidArgument):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, models.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, models.ErrConflict):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, models.ErrDependencyUnavailable):
		return status.Error(codes.Unavailable, err.Error())
	default:
		return status.Error(codes.Internal, "internal error")
	}
}
