package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"dispatch/models"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

func (s *Service) Preview(ctx context.Context, in *models.RecommendInput) ([]models.Candidate, error) {
	if in == nil || in.TicketID == uuid.Nil {
		return nil, fmt.Errorf("%w: ticket_id", models.ErrInvalidArgument)
	}
	if in.Limit <= 0 {
		in.Limit = 10
	}
	if in.Limit > 100 {
		return nil, fmt.Errorf("%w: limit must not exceed 100", models.ErrInvalidArgument)
	}
	ctx = forwardMetadata(ctx)
	ticket, err := s.getNewTicket(ctx, in.TicketID)
	if err != nil {
		return nil, err
	}
	available, err := s.deps.Brigades.GetAvailableBrigades(ctx, &brigadev1.GetAvailableBrigadesRequest{
		DepartmentId: ticket.GetDepartmentId(), Longitude: &ticket.Longitude, Latitude: &ticket.Latitude,
		RequiredSkillIds: uuidStrings(in.RequiredSkillIDs), Limit: max(in.Limit*3, 20),
	})
	if err != nil {
		return nil, fmt.Errorf("get available brigades: %w", err)
	}
	ids := make([]string, 0, len(available.GetBrigades()))
	for _, brigade := range available.GetBrigades() {
		ids = append(ids, brigade.GetId())
	}
	if len(ids) == 0 {
		return []models.Candidate{}, nil
	}
	locations, err := s.deps.Location.GetCurrentLocations(ctx, &locationv1.GetCurrentLocationsRequest{BrigadeIds: ids, AllowStale: false})
	if err != nil {
		return nil, fmt.Errorf("get brigade locations: %w", err)
	}
	candidates := make([]*routingv1.Candidate, 0, len(ids))
	for _, id := range ids {
		current := locations.GetLocations()[id]
		if current == nil || current.GetPosition() == nil {
			continue
		}
		candidates = append(candidates, &routingv1.Candidate{BrigadeId: id, Location: &routingv1.Point{Latitude: current.GetPosition().GetLatitude(), Longitude: current.GetPosition().GetLongitude()}})
	}
	ranked, err := s.deps.Routing.RankCandidates(ctx, &routingv1.RankCandidatesRequest{
		Destination: &routingv1.Point{Latitude: ticket.GetLatitude(), Longitude: ticket.GetLongitude()}, Candidates: candidates,
		Options: &routingv1.RouteOptions{TravelMode: routingv1.TravelMode_TRAVEL_MODE_AUTO}, Limit: in.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("rank candidates: %w", err)
	}
	result := make([]models.Candidate, 0, len(ranked.GetCandidates()))
	for _, item := range ranked.GetCandidates() {
		id, parseErr := uuid.Parse(item.GetBrigadeId())
		if parseErr != nil || item.GetLocation() == nil {
			continue
		}
		result = append(result, models.Candidate{BrigadeID: id, Rank: item.GetRank(), DistanceMeters: item.GetDistanceMeters(), ETASeconds: item.GetEtaSeconds(), Reachable: item.GetReachable(), Latitude: item.GetLocation().GetLatitude(), Longitude: item.GetLocation().GetLongitude()})
	}
	return result, nil
}

func (s *Service) Reserve(ctx context.Context, in *models.ReserveInput) (*models.Operation, error) {
	if in == nil || in.TicketID == uuid.Nil || in.BrigadeID == uuid.Nil || in.RequestedBy == uuid.Nil {
		return nil, fmt.Errorf("%w: reserve input", models.ErrInvalidArgument)
	}
	ttl := in.TTL
	if ttl <= 0 {
		ttl = s.ttl
	}
	if ttl < 15*time.Second || ttl > 15*time.Minute {
		return nil, fmt.Errorf("%w: reservation TTL must be between 15s and 15m", models.ErrInvalidArgument)
	}
	ctx = forwardMetadata(ctx)
	op, err := s.repo.Create(ctx, in.TicketID, in.RequestedBy, models.ModeManual, ttl)
	if err != nil {
		return nil, err
	}
	return s.reserveExisting(ctx, op, in.BrigadeID, in.RequiredSkillIDs, in.RequestedBy)
}

func (s *Service) AutoDispatch(ctx context.Context, in *models.AutoInput) (*models.Operation, error) {
	if in == nil || in.TicketID == uuid.Nil || in.RequestedBy == uuid.Nil {
		return nil, fmt.Errorf("%w: auto dispatch input", models.ErrInvalidArgument)
	}
	if in.CandidateLimit <= 0 {
		in.CandidateLimit = 10
	}
	ctx = forwardMetadata(ctx)
	candidates, err := s.Preview(ctx, &models.RecommendInput{TicketID: in.TicketID, RequiredSkillIDs: in.RequiredSkillIDs, Limit: in.CandidateLimit})
	if err != nil {
		return nil, err
	}
	op, err := s.repo.Create(ctx, in.TicketID, in.RequestedBy, models.ModeAutomatic, s.ttl)
	if err != nil {
		return nil, err
	}
	var lastErr error = errors.New("no reachable brigade")
	for _, candidate := range candidates {
		if !candidate.Reachable {
			continue
		}
		reserved, reserveErr := s.reserveExisting(ctx, op, candidate.BrigadeID, in.RequiredSkillIDs, in.RequestedBy)
		if reserveErr != nil {
			lastErr = reserveErr
			continue
		}
		return s.Confirm(ctx, &models.ConfirmInput{ID: reserved.ID, ConfirmedBy: in.RequestedBy, ExpectedVersion: reserved.Version})
	}
	_, _ = s.repo.SetFailed(ctx, op.ID, lastErr.Error(), op.Version)
	return nil, fmt.Errorf("auto dispatch: %w", lastErr)
}

func (s *Service) Confirm(ctx context.Context, in *models.ConfirmInput) (*models.Operation, error) {
	if in == nil || in.ID == uuid.Nil || in.ConfirmedBy == uuid.Nil || in.ExpectedVersion <= 0 {
		return nil, fmt.Errorf("%w: confirm input", models.ErrInvalidArgument)
	}
	ctx = forwardMetadata(ctx)
	op, err := s.repo.Get(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if op.Status != models.StatusReserved || op.Version != in.ExpectedVersion || op.BrigadeID == nil {
		return nil, models.ErrConflict
	}
	ticket, err := s.getNewTicket(ctx, op.TicketID)
	if err != nil {
		return s.failAndRelease(ctx, op, in.ConfirmedBy, err)
	}
	location, err := s.deps.Location.GetCurrentLocation(ctx, &locationv1.GetCurrentLocationRequest{SubjectType: locationv1.SubjectType_SUBJECT_TYPE_BRIGADE, SubjectId: op.BrigadeID.String()})
	if err != nil || location.GetLocation() == nil || location.GetLocation().GetPosition() == nil {
		if err == nil { err = errors.New("brigade location unavailable") }
		return s.failAndRelease(ctx, op, in.ConfirmedBy, err)
	}
	position := location.GetLocation().GetPosition()
	route, err := s.deps.Routing.CreateRoute(ctx, &routingv1.CreateRouteRequest{
		TicketId: op.TicketID.String(), BrigadeId: op.BrigadeID.String(),
		Origin: &routingv1.Point{Latitude: position.GetLatitude(), Longitude: position.GetLongitude()},
		Destination: &routingv1.Point{Latitude: ticket.GetLatitude(), Longitude: ticket.GetLongitude()},
		Options: &routingv1.RouteOptions{TravelMode: routingv1.TravelMode_TRAVEL_MODE_AUTO},
	})
	if err != nil || route.GetRoute() == nil {
		if err == nil { err = errors.New("routing returned an empty route") }
		return s.failAndRelease(ctx, op, in.ConfirmedBy, err)
	}
	routeID, err := uuid.Parse(route.GetRoute().GetId())
	if err != nil {
		s.cancelRoute(ctx, route.GetRoute().GetId())
		return s.failAndRelease(ctx, op, in.ConfirmedBy, err)
	}
	op, err = s.repo.BeginConfirm(ctx, op.ID, routeID, op.Version)
	if err != nil {
		s.cancelRoute(ctx, routeID.String())
		return nil, err
	}
	_, err = s.deps.Tickets.AssignBrigade(ctx, &ticketv1.AssignBrigadeRequest{TicketId: op.TicketID.String(), BrigadeId: op.BrigadeID.String(), AssignedBy: in.ConfirmedBy.String(), Comment: "assigned by dispatch"})
	if err != nil {
		s.cancelRoute(ctx, routeID.String())
		return s.failAndRelease(ctx, op, in.ConfirmedBy, fmt.Errorf("assign ticket: %w", err))
	}
	return s.repo.FinishConfirm(ctx, op.ID, op.Version)
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Operation, error) { return s.repo.Get(ctx, id) }

func (s *Service) List(ctx context.Context, in *models.ListInput) ([]*models.Operation, int64, error) {
	if in == nil { in = &models.ListInput{} }
	if in.Limit <= 0 { in.Limit = 50 }
	if in.Limit > 200 || in.Offset < 0 { return nil, 0, fmt.Errorf("%w: pagination", models.ErrInvalidArgument) }
	return s.repo.List(ctx, in)
}

func (s *Service) Cancel(ctx context.Context, in *models.CancelInput) (*models.Operation, error) {
	if in == nil || in.ID == uuid.Nil || in.CancelledBy == uuid.Nil || in.ExpectedVersion <= 0 {
		return nil, fmt.Errorf("%w: cancel input", models.ErrInvalidArgument)
	}
	op, err := s.repo.Get(ctx, in.ID)
	if err != nil { return nil, err }
	if op.Version != in.ExpectedVersion || (op.Status != models.StatusPending && op.Status != models.StatusReserved) { return nil, models.ErrConflict }
	if op.BrigadeID != nil { s.release(forwardMetadata(ctx), *op.BrigadeID, in.CancelledBy) }
	reason := in.Reason
	if reason == "" { reason = "cancelled by dispatcher" }
	return s.repo.SetTerminal(ctx, op.ID, models.StatusCancelled, reason, op.Version)
}

func (s *Service) reserveExisting(ctx context.Context, op *models.Operation, brigadeID uuid.UUID, skills []uuid.UUID, actor uuid.UUID) (*models.Operation, error) {
	ticket, err := s.getNewTicket(ctx, op.TicketID)
	if err != nil { return nil, err }
	check, err := s.deps.Brigades.CheckBrigadeCanHandleTicket(ctx, &brigadev1.CheckBrigadeCanHandleTicketRequest{BrigadeId: brigadeID.String(), DepartmentId: ticket.GetDepartmentId(), Longitude: ticket.GetLongitude(), Latitude: ticket.GetLatitude(), RequiredSkillIds: uuidStrings(skills)})
	if err != nil { return nil, fmt.Errorf("check brigade: %w", err) }
	if !check.GetCanHandle() { return nil, fmt.Errorf("%w: brigade cannot handle ticket: %v", models.ErrConflict, check.GetReasons()) }
	_, err = s.deps.Brigades.SetBrigadeStatus(ctx, &brigadev1.SetBrigadeStatusRequest{BrigadeId: brigadeID.String(), Status: brigadev1.BrigadeStatus_BRIGADE_STATUS_BUSY, Reason: "dispatch reservation", ChangedByUserId: actor.String()})
	if err != nil { return nil, fmt.Errorf("reserve brigade: %w", err) }
	reserved, err := s.repo.SetReserved(ctx, op.ID, brigadeID, op.Version)
	if err != nil { s.release(ctx, brigadeID, actor); return nil, err }
	return reserved, nil
}

func (s *Service) getNewTicket(ctx context.Context, id uuid.UUID) (*ticketv1.Ticket, error) {
	response, err := s.deps.Tickets.GetTicket(ctx, &ticketv1.GetTicketRequest{TicketId: id.String()})
	if err != nil { return nil, fmt.Errorf("get ticket: %w", err) }
	if response.GetTicket() == nil { return nil, models.ErrNotFound }
	if response.GetTicket().GetStatus() != ticketv1.TicketStatus_TICKET_STATUS_NEW { return nil, fmt.Errorf("%w: ticket is not NEW", models.ErrConflict) }
	return response.GetTicket(), nil
}

func (s *Service) failAndRelease(ctx context.Context, op *models.Operation, actor uuid.UUID, cause error) (*models.Operation, error) {
	if op.BrigadeID != nil { s.release(ctx, *op.BrigadeID, actor) }
	_, _ = s.repo.SetFailed(ctx, op.ID, cause.Error(), op.Version)
	return nil, cause
}

func (s *Service) release(ctx context.Context, id, actor uuid.UUID) {
	_, err := s.deps.Brigades.SetBrigadeStatus(ctx, &brigadev1.SetBrigadeStatusRequest{BrigadeId: id.String(), Status: brigadev1.BrigadeStatus_BRIGADE_STATUS_AVAILABLE, Reason: "dispatch reservation released", ChangedByUserId: actor.String()})
	if err != nil { s.log.Error("release brigade", zap.Error(err), zap.String("brigade_id", id.String())) }
}

func (s *Service) cancelRoute(ctx context.Context, id string) {
	_, err := s.deps.Routing.SetRouteStatus(ctx, &routingv1.SetRouteStatusRequest{Id: id, Status: routingv1.RouteStatus_ROUTE_STATUS_CANCELLED})
	if err != nil { s.log.Error("cancel route", zap.Error(err), zap.String("route_id", id)) }
}

func forwardMetadata(ctx context.Context) context.Context {
	if outgoing, ok := metadata.FromOutgoingContext(ctx); ok && len(outgoing) > 0 { return ctx }
	if incoming, ok := metadata.FromIncomingContext(ctx); ok { return metadata.NewOutgoingContext(ctx, incoming.Copy()) }
	return ctx
}

func uuidStrings(values []uuid.UUID) []string {
	result := make([]string, 0, len(values))
	for _, value := range values { result = append(result, value.String()) }
	return result
}
