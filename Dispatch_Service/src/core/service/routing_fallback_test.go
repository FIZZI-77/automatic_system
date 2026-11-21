package service

import (
	"context"
	"dispatch/models"
	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

type fallbackTickets struct {
	ticketv1.TicketServiceClient
	ticket    *ticketv1.Ticket
	assigned  int
	assignErr error
}

func (f *fallbackTickets) GetTicket(context.Context, *ticketv1.GetTicketRequest, ...grpc.CallOption) (*ticketv1.GetTicketResponse, error) {
	return &ticketv1.GetTicketResponse{Ticket: f.ticket}, nil
}
func (f *fallbackTickets) AssignBrigade(_ context.Context, q *ticketv1.AssignBrigadeRequest, _ ...grpc.CallOption) (*ticketv1.AssignBrigadeResponse, error) {
	f.assigned++
	if f.assignErr != nil {
		return nil, f.assignErr
	}
	f.ticket.BrigadeId = q.BrigadeId
	return &ticketv1.AssignBrigadeResponse{}, nil
}

type fallbackBrigades struct {
	brigadev1.BrigadeServiceClient
	ids      []uuid.UUID
	released int
}

func (f *fallbackBrigades) GetAvailableBrigades(context.Context, *brigadev1.GetAvailableBrigadesRequest, ...grpc.CallOption) (*brigadev1.GetAvailableBrigadesResponse, error) {
	v := &brigadev1.GetAvailableBrigadesResponse{}
	for _, id := range f.ids {
		v.Brigades = append(v.Brigades, &brigadev1.Brigade{Id: id.String()})
	}
	return v, nil
}
func (f *fallbackBrigades) CheckBrigadeCanHandleTicket(context.Context, *brigadev1.CheckBrigadeCanHandleTicketRequest, ...grpc.CallOption) (*brigadev1.CheckBrigadeCanHandleTicketResponse, error) {
	return &brigadev1.CheckBrigadeCanHandleTicketResponse{CanHandle: true}, nil
}
func (f *fallbackBrigades) SetBrigadeStatus(_ context.Context, q *brigadev1.SetBrigadeStatusRequest, _ ...grpc.CallOption) (*brigadev1.SetBrigadeStatusResponse, error) {
	if q.Status == brigadev1.BrigadeStatus_BRIGADE_STATUS_AVAILABLE {
		f.released++
	}
	return &brigadev1.SetBrigadeStatusResponse{}, nil
}

type fallbackLocations struct {
	locationv1.LocationServiceClient
	locations map[string]*locationv1.CurrentLocation
	err       error
}

func (f *fallbackLocations) GetCurrentLocations(context.Context, *locationv1.GetCurrentLocationsRequest, ...grpc.CallOption) (*locationv1.GetCurrentLocationsResponse, error) {
	return &locationv1.GetCurrentLocationsResponse{Locations: f.locations}, f.err
}
func (f *fallbackLocations) GetCurrentLocation(_ context.Context, q *locationv1.GetCurrentLocationRequest, _ ...grpc.CallOption) (*locationv1.GetCurrentLocationResponse, error) {
	return &locationv1.GetCurrentLocationResponse{Location: f.locations[q.SubjectId]}, f.err
}

type fallbackRouting struct {
	routingv1.RoutingServiceClient
	err     error
	calls   int
	routeID uuid.UUID
}

func (f *fallbackRouting) RankCandidates(context.Context, *routingv1.RankCandidatesRequest, ...grpc.CallOption) (*routingv1.RankCandidatesResponse, error) {
	f.calls++
	return nil, f.err
}
func (f *fallbackRouting) CreateRoute(context.Context, *routingv1.CreateRouteRequest, ...grpc.CallOption) (*routingv1.CreateRouteResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &routingv1.CreateRouteResponse{Route: &routingv1.Route{Id: f.routeID.String()}}, nil
}

func TestPreviewRoutingOutageFallsBackToDistance(t *testing.T) {
	t.Parallel()
	near, far := uuid.New(), uuid.New()
	for _, tt := range []struct {
		name     string
		code     codes.Code
		fallback bool
	}{{"unavailable", codes.Unavailable, true}, {"timeout", codes.DeadlineExceeded, true}, {"overloaded", codes.ResourceExhausted, true}, {"forbidden", codes.PermissionDenied, false}, {"invalid", codes.InvalidArgument, false}} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			routing := &fallbackRouting{err: status.Error(tt.code, "routing result")}
			svc := &Service{log: zap.NewNop(), deps: Dependencies{Tickets: &fallbackTickets{ticket: &ticketv1.Ticket{Status: ticketv1.TicketStatus_TICKET_STATUS_NEW}}, Brigades: &fallbackBrigades{ids: []uuid.UUID{far, near}}, Location: &fallbackLocations{locations: map[string]*locationv1.CurrentLocation{near.String(): {Position: &locationv1.Position{Latitude: .01}}, far.String(): {Position: &locationv1.Position{Latitude: 1}}}}, Routing: routing}}
			got, err := svc.Preview(context.Background(), &models.RecommendInput{TicketID: uuid.New(), Limit: 1})
			if !tt.fallback {
				if status.Code(err) != tt.code {
					t.Fatalf("Preview(%v) = %v; want unchanged error", tt.code, err)
				}
				return
			}
			if err != nil || len(got) != 1 || got[0].BrigadeID != near || got[0].ETASeconds != -1 || !got[0].Reachable || got[0].Rank != 1 || got[0].DistanceMeters < 1100 || got[0].DistanceMeters > 1120 {
				t.Fatalf("Preview(%v) = %+v, %v; want nearest candidate with unknown ETA", tt.code, got, err)
			}
		})
	}
}
func TestPreviewRequiresFreshLocations(t *testing.T) {
	t.Parallel()
	routing := &fallbackRouting{}
	svc := &Service{log: zap.NewNop(), deps: Dependencies{Tickets: &fallbackTickets{ticket: &ticketv1.Ticket{Status: ticketv1.TicketStatus_TICKET_STATUS_NEW}}, Brigades: &fallbackBrigades{ids: []uuid.UUID{uuid.New()}}, Location: &fallbackLocations{err: status.Error(codes.Unavailable, "location offline")}, Routing: routing}}
	if _, err := svc.Preview(context.Background(), &models.RecommendInput{TicketID: uuid.New()}); status.Code(err) != codes.Unavailable || routing.calls != 0 {
		t.Fatalf("Preview(location outage) = %v routing calls=%d; want fail before routing", err, routing.calls)
	}
}
