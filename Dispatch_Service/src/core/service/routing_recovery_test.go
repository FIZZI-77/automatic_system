package service

import (
	"context"
	"dispatch/models"
	"dispatch/src/core/repository"
	"errors"
	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"testing"
	"time"
)

func TestAutomaticDispatchWithoutRouting(t *testing.T) {
	for _, tt := range []struct {
		name   string
		resume bool
	}{{"complete auto workflow", false}, {"restart after degraded confirm persisted", true}} {
		t.Run(tt.name, func(t *testing.T) {
			pool := recoveryPool(t)
			repo := repository.New(pool, pool)
			actor, department, brigade, ticketID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
			tickets := &fallbackTickets{ticket: &ticketv1.Ticket{Id: ticketID.String(), DepartmentId: department.String(), CategoryId: uuid.NewString(), Priority: ticketv1.TicketPriority_TICKET_PRIORITY_HIGH, Status: ticketv1.TicketStatus_TICKET_STATUS_NEW}}
			brigades := &fallbackBrigades{ids: []uuid.UUID{brigade}}
			locations := &fallbackLocations{locations: map[string]*locationv1.CurrentLocation{brigade.String(): {Position: &locationv1.Position{Latitude: .01}}}}
			routing := &fallbackRouting{err: status.Error(codes.Unavailable, "routing offline")}
			svc := &Service{repo: repo, deps: Dependencies{Tickets: tickets, Brigades: brigades, Location: locations, Routing: routing}, ttl: time.Minute, log: zap.NewNop()}
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-actor-user-id", actor.String(), "x-actor-roles", "admin"))
			var op *models.Operation
			var err error
			if tt.resume {
				op, err = repo.Create(ctx, models.CreateOperationInput{TicketID: ticketID, DepartmentID: department, CategoryID: uuid.New(), RequestedBy: actor, Mode: models.ModeAutomatic, TTL: time.Minute})
				if err != nil {
					t.Fatal(err)
				}
				op, err = repo.SetReserved(ctx, op.ID, brigade, op.Version)
				if err != nil {
					t.Fatal(err)
				}
				op, err = repo.BeginConfirmWithoutRoute(ctx, op.ID, op.Version)
				if err != nil {
					t.Fatal(err)
				}
				// Новый экземпляр восстанавливает операцию только по сохранённой записи CONFIRMING.
				svc = &Service{repo: repository.New(pool, pool), deps: Dependencies{Tickets: tickets}, log: zap.NewNop()}
				op, err = svc.resumeAutomatic(ctx, op, &models.AutoInput{TicketID: ticketID, RequestedBy: actor})
			} else {
				op, err = svc.AutoDispatch(ctx, &models.AutoInput{TicketID: ticketID, RequestedBy: actor, CandidateLimit: 1})
			}
			if err != nil || op.Status != models.StatusAssigned || op.RouteID != nil || op.BrigadeID == nil || *op.BrigadeID != brigade || tickets.assigned != 1 {
				t.Fatalf("AutoDispatch(outage/resume=%v) = %+v, %v assignments=%d; want assigned without route", tt.resume, op, err, tickets.assigned)
			}
			var count int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM dispatch_outbox_events WHERE aggregate_id=$1 AND event_type='dispatch.routing_degraded'`, op.ID).Scan(&count); err != nil || count != 1 {
				t.Fatalf("degraded outbox count = %d, %v; want 1", count, err)
			}
			var degraded bool
			if err := pool.QueryRow(ctx, `SELECT (payload->>'routing_degraded')::boolean FROM dispatch_outbox_events WHERE aggregate_id=$1 AND event_type='dispatch.assigned'`, op.ID).Scan(&degraded); err != nil || !degraded {
				t.Fatalf("assigned event routing_degraded = %v, %v; want true", degraded, err)
			}
		})
	}
}
func TestManualConfirmStillRequiresRoute(t *testing.T) {
	pool := recoveryPool(t)
	repo := repository.New(pool, pool)
	actor, department, brigade := uuid.New(), uuid.New(), uuid.New()
	op := reservedOperation(t, repo, actor, department, brigade)
	if _, err := repo.BeginConfirmWithoutRoute(t.Context(), op.ID, op.Version); !errors.Is(err, models.ErrConflict) {
		t.Fatalf("BeginConfirmWithoutRoute(manual) = %v; want conflict", err)
	}
	tickets := &fallbackTickets{ticket: &ticketv1.Ticket{Status: ticketv1.TicketStatus_TICKET_STATUS_NEW}}
	brigades := &fallbackBrigades{}
	svc := &Service{repo: repo, log: zap.NewNop(), deps: Dependencies{Tickets: tickets, Brigades: brigades, Location: &fallbackLocations{locations: map[string]*locationv1.CurrentLocation{brigade.String(): {Position: &locationv1.Position{}}}}, Routing: &fallbackRouting{err: status.Error(codes.Unavailable, "routing offline")}}}
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("x-actor-roles", "admin"))
	if _, err := svc.Confirm(ctx, &models.ConfirmInput{ID: op.ID, ConfirmedBy: actor, ExpectedVersion: op.Version}); status.Code(err) != codes.Unavailable {
		t.Fatalf("Confirm(manual outage) = %v; want unavailable", err)
	}
	stored, err := repo.Get(ctx, op.ID)
	if err != nil || stored.Status != models.StatusFailed || tickets.assigned != 0 || brigades.released != 1 {
		t.Fatalf("manual outage state = %+v, %v assignments=%d releases=%d", stored, err, tickets.assigned, brigades.released)
	}
}

func TestAutomaticRoutingFallbackCompensatesAssignmentFailure(t *testing.T) {
	pool := recoveryPool(t)
	repo := repository.New(pool, pool)
	ctx := t.Context()
	actor, department, brigade, ticketID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	op, err := repo.Create(ctx, models.CreateOperationInput{TicketID: ticketID, DepartmentID: department, CategoryID: uuid.New(), RequestedBy: actor, Mode: models.ModeAutomatic, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	op, err = repo.SetReserved(ctx, op.ID, brigade, op.Version)
	if err != nil {
		t.Fatal(err)
	}
	op, err = repo.BeginConfirmWithoutRoute(ctx, op.ID, op.Version)
	if err != nil {
		t.Fatal(err)
	}
	brigades := &fallbackBrigades{}
	tickets := &fallbackTickets{ticket: &ticketv1.Ticket{Status: ticketv1.TicketStatus_TICKET_STATUS_NEW}, assignErr: status.Error(codes.Unavailable, "ticket offline")}
	svc := &Service{repo: repo, log: zap.NewNop(), deps: Dependencies{Tickets: tickets, Brigades: brigades}}
	if _, err := svc.finishConfirm(ctx, op, actor); status.Code(err) != codes.Unavailable {
		t.Fatalf("finishConfirm(no route, assignment failure) = %v; want unavailable", err)
	}
	stored, err := repo.Get(ctx, op.ID)
	if err != nil || stored.Status != models.StatusFailed || stored.ReleasePending || brigades.released != 1 {
		t.Fatalf("compensated operation = %+v, %v releases=%d; want FAILED with released reservation", stored, err, brigades.released)
	}
}
