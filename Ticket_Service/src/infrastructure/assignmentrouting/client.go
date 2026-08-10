package assignmentrouting

import (
	"context"
	"errors"
	"fmt"

	"ticket/models"
	"ticket/src/core/service"

	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	"github.com/google/uuid"
)

type Client struct {
	location locationv1.LocationServiceClient
	routing  routingv1.RoutingServiceClient
}

func New(location locationv1.LocationServiceClient, routing routingv1.RoutingServiceClient) (*Client, error) {
	if location == nil || routing == nil {
		return nil, errors.New("assignment routing: location and routing clients are required")
	}
	return &Client{location: location, routing: routing}, nil
}

func (c *Client) CreateForAssignment(ctx context.Context, ticket *models.Ticket, brigadeID uuid.UUID) (*service.RouteReservation, error) {
	if ticket == nil {
		return nil, errors.New("assignment routing: ticket is required")
	}
	if existing, err := c.openRoute(ctx, ticket.ID.String()); err != nil {
		return nil, err
	} else if existing != nil {
		if existing.GetBrigadeId() != brigadeID.String() {
			return nil, errors.New("assignment routing: ticket already has a route for another brigade")
		}
		return &service.RouteReservation{RouteID: existing.GetId()}, nil
	}

	location, err := c.location.GetCurrentLocation(ctx, &locationv1.GetCurrentLocationRequest{
		SubjectType: locationv1.SubjectType_SUBJECT_TYPE_BRIGADE,
		SubjectId:   brigadeID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("assignment routing: get brigade location: %w", err)
	}
	if location.GetLocation() == nil || location.GetLocation().GetPosition() == nil {
		return nil, errors.New("assignment routing: brigade location is unavailable")
	}
	if location.GetLocation().GetSignalStatus() == locationv1.SignalStatus_SIGNAL_STATUS_OFFLINE {
		return nil, errors.New("assignment routing: brigade signal is offline")
	}
	position := location.GetLocation().GetPosition()
	created, err := c.routing.CreateRoute(ctx, &routingv1.CreateRouteRequest{
		TicketId:  ticket.ID.String(),
		BrigadeId: brigadeID.String(),
		Origin: &routingv1.Point{
			Latitude: position.GetLatitude(), Longitude: position.GetLongitude(),
		},
		Destination: &routingv1.Point{
			Latitude: ticket.Latitude, Longitude: ticket.Longitude,
		},
		Options: &routingv1.RouteOptions{TravelMode: routingv1.TravelMode_TRAVEL_MODE_AUTO},
	})
	if err != nil {
		return nil, fmt.Errorf("assignment routing: create route: %w", err)
	}
	if created.GetRoute() == nil || created.GetRoute().GetId() == "" {
		return nil, errors.New("assignment routing: routing returned an empty route")
	}
	return &service.RouteReservation{RouteID: created.GetRoute().GetId(), Created: true}, nil
}

func (c *Client) Cancel(ctx context.Context, routeID string) error {
	_, err := c.routing.SetRouteStatus(ctx, &routingv1.SetRouteStatusRequest{Id: routeID, Status: routingv1.RouteStatus_ROUTE_STATUS_CANCELLED})
	if err != nil {
		return fmt.Errorf("assignment routing: cancel route: %w", err)
	}
	return nil
}

func (c *Client) openRoute(ctx context.Context, ticketID string) (*routingv1.Route, error) {
	for _, status := range []routingv1.RouteStatus{routingv1.RouteStatus_ROUTE_STATUS_PLANNED, routingv1.RouteStatus_ROUTE_STATUS_ACTIVE} {
		value := status
		result, err := c.routing.ListRoutes(ctx, &routingv1.ListRoutesRequest{TicketId: &ticketID, Status: &value, Limit: 1})
		if err != nil {
			return nil, fmt.Errorf("assignment routing: list routes: %w", err)
		}
		if len(result.GetRoutes()) > 0 {
			return result.GetRoutes()[0], nil
		}
	}
	return nil, nil
}
