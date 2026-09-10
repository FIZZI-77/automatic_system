package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"gateway/models"

	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type RoutingHandler struct {
	client routingv1.RoutingServiceClient
}

func NewRoutingHandler(
	client routingv1.RoutingServiceClient,
) *RoutingHandler {
	return &RoutingHandler{client: client}
}

func (h *RoutingHandler) BuildRoute(c *gin.Context) {
	var input models.BuildRouteRequest
	if !bindJSON(c, &input) {
		return
	}
	response, err := h.client.BuildRoute(
		routingContext(c),
		&routingv1.BuildRouteRequest{
			Origin:      routingPoint(input.Origin),
			Destination: routingPoint(input.Destination),
			Waypoints:   routingPoints(input.Waypoints),
			Options:     routingOptions(input.Options),
		},
	)
	routingResponse(c, http.StatusOK, err, response)
}

func (h *RoutingHandler) BuildMatrix(c *gin.Context) {
	var input models.BuildMatrixRequest
	if !bindJSON(c, &input) {
		return
	}
	response, err := h.client.BuildMatrix(
		routingContext(c),
		&routingv1.BuildMatrixRequest{
			Sources: routingPoints(input.Sources),
			Targets: routingPoints(input.Targets),
			Options: routingOptions(input.Options),
		},
	)
	routingResponse(c, http.StatusOK, err, response)
}

func (h *RoutingHandler) RankCandidates(c *gin.Context) {
	var input models.RankCandidatesRequest
	if !bindJSON(c, &input) {
		return
	}
	candidates := make([]*routingv1.Candidate, 0, len(input.Candidates))
	for _, candidate := range input.Candidates {
		candidates = append(candidates, &routingv1.Candidate{
			BrigadeId: candidate.BrigadeID,
			Location:  routingPoint(candidate.Location),
		})
	}
	response, err := h.client.RankCandidates(
		routingContext(c),
		&routingv1.RankCandidatesRequest{
			Destination: routingPoint(input.Destination),
			Candidates:  candidates,
			Options:     routingOptions(input.Options),
			Limit:       input.Limit,
		},
	)
	routingResponse(c, http.StatusOK, err, response)
}

func (h *RoutingHandler) CreateRoute(c *gin.Context) {
	var input models.CreateRoutingRouteRequest
	if !bindJSON(c, &input) {
		return
	}
	response, err := h.client.CreateRoute(
		routingContext(c),
		&routingv1.CreateRouteRequest{
			TicketId:    input.TicketID,
			BrigadeId:   input.BrigadeID,
			Origin:      routingPoint(input.Origin),
			Destination: routingPoint(input.Destination),
			Waypoints:   routingPoints(input.Waypoints),
			Options:     routingOptions(input.Options),
		},
	)
	routingResponse(c, http.StatusCreated, err, response)
}

func (h *RoutingHandler) GetRoute(c *gin.Context) {
	var input models.GetRoutingRouteRequest
	if !bindJSON(c, &input) {
		return
	}
	response, err := h.client.GetRoute(
		routingContext(c),
		&routingv1.GetRouteRequest{Id: input.ID},
	)
	routingResponse(c, http.StatusOK, err, response)
}

func (h *RoutingHandler) RecalculateRoute(c *gin.Context) {
	var input models.RecalculateRoutingRouteRequest
	if !bindJSON(c, &input) {
		return
	}
	response, err := h.client.RecalculateRoute(
		routingContext(c),
		&routingv1.RecalculateRouteRequest{
			Id:              input.ID,
			CurrentPosition: routingPoint(input.CurrentPosition),
		},
	)
	routingResponse(c, http.StatusOK, err, response)
}

func (h *RoutingHandler) SetRouteStatus(c *gin.Context) {
	var input models.SetRoutingRouteStatusRequest
	if !bindJSON(c, &input) {
		return
	}
	response, err := h.client.SetRouteStatus(
		routingContext(c),
		&routingv1.SetRouteStatusRequest{
			Id:     input.ID,
			Status: routingStatus(input.Status),
		},
	)
	routingResponse(c, http.StatusOK, err, response)
}

func (h *RoutingHandler) ListRoutes(c *gin.Context) {
	var input models.ListRoutingRoutesRequest
	if !bindJSON(c, &input) {
		return
	}
	request := &routingv1.ListRoutesRequest{
		TicketId:  input.TicketID,
		BrigadeId: input.BrigadeID,
		Limit:     input.Limit,
		Offset:    input.Offset,
	}
	if input.Status != nil {
		value := routingStatus(*input.Status)
		request.Status = &value
	}
	response, err := h.client.ListRoutes(routingContext(c), request)
	routingResponse(c, http.StatusOK, err, response)
}

func routingPoint(value models.RoutingPoint) *routingv1.Point {
	return &routingv1.Point{
		Latitude:  value.Latitude,
		Longitude: value.Longitude,
	}
}

func routingPoints(values []models.RoutingPoint) []*routingv1.Point {
	result := make([]*routingv1.Point, 0, len(values))
	for _, value := range values {
		result = append(result, routingPoint(value))
	}
	return result
}

func routingOptions(value models.RoutingOptions) *routingv1.RouteOptions {
	result := &routingv1.RouteOptions{
		TravelMode:   routingMode(value.TravelMode),
		Alternatives: value.Alternatives,
	}
	if strings.TrimSpace(value.DepartureAt) != "" {
		parsed, err := time.Parse(time.RFC3339, value.DepartureAt)
		if err == nil {
			result.DepartureAt = timestamppb.New(parsed)
		}
	}
	if value.Vehicle != nil {
		result.Vehicle = &routingv1.VehicleConstraints{
			HeightMeters:       value.Vehicle.HeightMeters,
			WidthMeters:        value.Vehicle.WidthMeters,
			LengthMeters:       value.Vehicle.LengthMeters,
			WeightTons:         value.Vehicle.WeightTons,
			AxleLoadTons:       value.Vehicle.AxleLoadTons,
			HazardousMaterials: value.Vehicle.HazardousMaterials,
		}
	}
	return result
}

func routingMode(value string) routingv1.TravelMode {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "truck":
		return routingv1.TravelMode_TRAVEL_MODE_TRUCK
	case "bicycle":
		return routingv1.TravelMode_TRAVEL_MODE_BICYCLE
	case "pedestrian":
		return routingv1.TravelMode_TRAVEL_MODE_PEDESTRIAN
	default:
		return routingv1.TravelMode_TRAVEL_MODE_AUTO
	}
}

func routingStatus(value string) routingv1.RouteStatus {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "ACTIVE":
		return routingv1.RouteStatus_ROUTE_STATUS_ACTIVE
	case "COMPLETED":
		return routingv1.RouteStatus_ROUTE_STATUS_COMPLETED
	case "CANCELLED":
		return routingv1.RouteStatus_ROUTE_STATUS_CANCELLED
	default:
		return routingv1.RouteStatus_ROUTE_STATUS_PLANNED
	}
}

func routingContext(c *gin.Context) context.Context {
	ctx, cancel := context.WithTimeout(
		c.Request.Context(),
		15*time.Second,
	)
	c.Set("routing_cancel", cancel)
	return gatewayActorContext(ctx, c)
}

func routingResponse(
	c *gin.Context,
	statusCode int,
	err error,
	response any,
) {
	if value, ok := c.Get("routing_cancel"); ok {
		if cancel, valid := value.(context.CancelFunc); valid {
			cancel()
		}
	}
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	c.JSON(statusCode, response)
}
