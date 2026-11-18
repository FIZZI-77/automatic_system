package handler

import (
	"context"
	"fmt"
	"testing"

	reportv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/report/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"report/models"
	"report/src/core/service"
)

type accessService struct {
	service.ReportService
	actor      uuid.UUID
	privileged bool
	err        error
}

func (s *accessService) Get(_ context.Context, id, actor uuid.UUID, p bool) (*models.Report, error) {
	s.actor = actor
	s.privileged = p
	return &models.Report{ID: id, RequestedBy: actor}, s.err
}
func TestReportHandlerAccess(t *testing.T) {
	t.Parallel()
	actor, id := uuid.New(), uuid.New()
	for _, tt := range []struct {
		name       string
		roles      []string
		privileged bool
	}{
		{name: "user", roles: []string{"user"}}, {name: "admin", roles: []string{"admin"}, privileged: true}, {name: "dispatcher", roles: []string{"dispatcher"}, privileged: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &accessService{}
			h := New(s)
			got, err := h.GetReport(context.Background(), &reportv1.GetReportRequest{ReportId: id.String(), ActorUserId: actor.String(), ActorRoles: tt.roles})
			if err != nil || got.Report.Id != id.String() || s.actor != actor || s.privileged != tt.privileged {
				t.Fatalf("GetReport(%q) = %v,%v actor=%v privileged=%v", tt.name, got, err, s.actor, s.privileged)
			}
			s.err = models.ErrForbidden
			if _, err := h.GetReport(context.Background(), &reportv1.GetReportRequest{ReportId: id.String(), ActorUserId: actor.String()}); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("GetReport(forbidden) = %v", err)
			}
		})
	}
	for _, q := range []*reportv1.GetReportRequest{{ReportId: "bad", ActorUserId: actor.String()}, {ReportId: id.String(), ActorUserId: "bad"}} {
		if _, err := New(nil).GetReport(context.Background(), q); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("GetReport(%+v) = %v; want invalid argument", q, err)
		}
	}
}
func TestReportErrorMapping(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		err  error
		want codes.Code
	}{{fmt.Errorf("wrapped: %w", pgx.ErrNoRows), codes.NotFound}, {models.ErrForbidden, codes.PermissionDenied}, {models.ErrInvalidState, codes.FailedPrecondition}, {context.Canceled, codes.InvalidArgument}} {
		if got := status.Code(mapErr(tt.err)); got != tt.want {
			t.Errorf("mapErr(%v) = %v; want %v", tt.err, got, tt.want)
		}
	}
}
