package handler

import (
	"context"
	"testing"

	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"routing/models"
	"routing/src/core/service"
)

type ticketAccessStub struct {
	ticketv1.TicketServiceClient
	allowed string
}

func (s ticketAccessStub) GetTicket(ctx context.Context, request *ticketv1.GetTicketRequest, _ ...grpc.CallOption) (*ticketv1.GetTicketResponse, error) {
	if request.GetTicketId() != s.allowed {
		return nil, status.Error(codes.PermissionDenied, "foreign ticket")
	}
	return &ticketv1.GetTicketResponse{Ticket: &ticketv1.Ticket{Id: s.allowed}}, nil
}

func (s ticketAccessStub) ListTickets(context.Context, *ticketv1.ListTicketsRequest, ...grpc.CallOption) (*ticketv1.ListTicketsResponse, error) {
	return &ticketv1.ListTicketsResponse{Tickets: []*ticketv1.Ticket{{Id: s.allowed}}}, nil
}

type routeAccessStub struct {
	service.RoutingService
	route   *models.Route
	mutated bool
	scope   []string
}

func (s *routeAccessStub) GetRoute(context.Context, string) (*models.Route, error) {
	return s.route, nil
}
func (s *routeAccessStub) SetRouteStatus(context.Context, string, models.RouteStatus) (*models.Route, error) {
	s.mutated = true
	return s.route, nil
}
func (s *routeAccessStub) ListRoutes(_ context.Context, in *models.ListRoutesInput) (*models.ListRoutesResult, error) {
	s.scope = in.AllowedTicketIDs
	return &models.ListRoutesResult{}, nil
}

func routeActor(role string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-actor-user-id", uuid.NewString(), "x-actor-roles", role))
}

func TestRouteAuthorizationStopsForeignReadAndStatusMutation(t *testing.T) {
	own, foreign := uuid.NewString(), uuid.NewString()
	svc := &routeAccessStub{route: &models.Route{ID: uuid.NewString(), TicketID: foreign}}
	h := New(svc, ticketAccessStub{allowed: own}, nil)
	if _, err := h.GetRoute(routeActor("user"), &routingv1.GetRouteRequest{Id: svc.route.ID}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("foreign route read=%v", err)
	}
	for _, role := range []string{"user", "worker", "dispatcher"} {
		_, err := h.SetRouteStatus(routeActor(role), &routingv1.SetRouteStatusRequest{Id: svc.route.ID, Status: routingv1.RouteStatus_ROUTE_STATUS_ACTIVE})
		if status.Code(err) != codes.PermissionDenied || svc.mutated {
			t.Fatalf("role=%s mutation=%v error=%v", role, svc.mutated, err)
		}
	}
	svc.route.TicketID = own
	if _, err := h.GetRoute(routeActor("worker"), &routingv1.GetRouteRequest{Id: svc.route.ID}); err != nil {
		t.Fatalf("allowed worker read=%v", err)
	}
	if _, err := h.SetRouteStatus(routeActor("dispatcher"), &routingv1.SetRouteStatusRequest{Id: svc.route.ID, Status: routingv1.RouteStatus_ROUTE_STATUS_ACTIVE}); err != nil || !svc.mutated {
		t.Fatalf("allowed dispatcher mutation=%v err=%v", svc.mutated, err)
	}
}

func TestRouteListScopesBeforeRepositoryPagination(t *testing.T) {
	own := uuid.NewString()
	svc := &routeAccessStub{}
	h := New(svc, ticketAccessStub{allowed: own}, nil)
	if _, err := h.ListRoutes(routeActor("dispatcher"), &routingv1.ListRoutesRequest{}); err != nil {
		t.Fatal(err)
	}
	if len(svc.scope) != 1 || svc.scope[0] != own {
		t.Fatalf("scope=%v", svc.scope)
	}
	foreign := uuid.NewString()
	if _, err := h.ListRoutes(routeActor("user"), &routingv1.ListRoutesRequest{TicketId: &foreign}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("foreign filter=%v", err)
	}
	if _, err := h.ListRoutes(context.Background(), &routingv1.ListRoutesRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing actor=%v", err)
	}
	if _, err := h.ListRoutes(routeActor("admin"), &routingv1.ListRoutesRequest{}); err != nil || svc.scope != nil {
		t.Fatalf("admin scope=%v error=%v", svc.scope, err)
	}
}
