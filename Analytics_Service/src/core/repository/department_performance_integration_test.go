//go:build integration

package repository

import (
	"analytics/models"
	"context"
	"math"
	"os"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

func TestDepartmentPerformanceInClickHouse(t *testing.T) {
	address := os.Getenv("CLICKHOUSE_TEST_ADDR")

	if address == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR is not set")
	}

	ctx := context.Background()
	db, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{address},
		Auth: clickhouse.Auth{Database: "analytics", Username: "analytics", Password: os.Getenv("CLICKHOUSE_TEST_PASSWORD")},
	})

	if err != nil {
		t.Fatalf("clickhouse.Open: %v", err)
	}

	t.Cleanup(func() { _ = db.Close() })
	repo := NewAnalyticsRepoStruct(db)
	departmentID := uuid.NewString()
	otherDepartmentID := uuid.NewString()
	ticketID := uuid.NewString()
	openTicketID := uuid.NewString()
	otherTicketID := uuid.NewString()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)

	events := []models.Event{
		analyticsEvent(ticketID, "ticket.created", start, map[string]any{"ticket_id": ticketID, "department_id": departmentID, "status": "NEW"}),
		analyticsEvent(ticketID, "ticket.assigned", start.Add(time.Minute), map[string]any{"ticket_id": ticketID, "department_id": departmentID, "status": "ASSIGNED"}),
		analyticsEvent(ticketID, "ticket.completed", start.Add(10*time.Minute), map[string]any{"ticket_id": ticketID, "department_id": departmentID, "status": "DONE"}),
		analyticsEvent(ticketID, "ticket.feedback_submitted", start.Add(11*time.Minute), map[string]any{"ticket_id": ticketID, "department_id": departmentID, "rating": 4, "problem_resolved": false}),
		analyticsEvent(openTicketID, "ticket.created", start.Add(2*time.Minute), map[string]any{"ticket_id": openTicketID, "department_id": departmentID, "status": "NEW"}),
		analyticsEvent(otherTicketID, "ticket.created", start.Add(3*time.Minute), map[string]any{"ticket_id": otherTicketID, "department_id": otherDepartmentID, "status": "NEW"}),
		{ID: uuid.NewString(), Type: "sla.RESPONSE_RECORDED", Topic: "sla.events.v1", Timestamp: start.Add(time.Minute), Version: 1, ProjectionEligible: true, Payload: map[string]any{
			"ticket_id": ticketID, "response_deadline": start.Add(2 * time.Minute).Format(time.RFC3339Nano),
			"responded_at": start.Add(time.Minute).Format(time.RFC3339Nano), "response_breached": false,
		}},
		{ID: uuid.NewString(), Type: "sla.COMPLETED", Topic: "sla.events.v1", Timestamp: start.Add(10 * time.Minute), Version: 1, ProjectionEligible: true, Payload: map[string]any{
			"ticket_id": ticketID, "resolution_deadline": start.Add(8 * time.Minute).Format(time.RFC3339Nano),
			"completed_at": start.Add(10 * time.Minute).Format(time.RFC3339Nano), "resolution_breached": true,
		}},
	}

	for _, event := range events {

		if err = repo.Store(ctx, event); err != nil {
			t.Fatalf("Store(%s): %v", event.Type, err)
		}

	}

	from, to := start.Add(-time.Minute), start.Add(4*time.Minute)
	report, err := repo.DepartmentPerformance(ctx, models.Filter{From: &from, To: &to})

	if err != nil {
		t.Fatalf("DepartmentPerformance: %v", err)
	}

	if len(report.Departments) != 2 || report.Organization.Created != 3 || report.Organization.Completed != 1 {
		t.Fatalf("unexpected organization report: %+v", report)
	}

	var department models.DepartmentPerformance
	for _, item := range report.Departments {

		if item.DepartmentID == departmentID {
			department = item
		}

	}

	if department.Created != 2 || department.FeedbackCount != 1 || department.AverageRating != 4 || department.ResolvedFeedbackRate != 0 {
		t.Fatalf("unexpected feedback metrics: %+v", department)
	}

	if department.ResponseSampleCount != 1 || department.ResolutionSampleCount != 1 {
		t.Fatalf("unexpected duration samples: %+v", department)
	}

	if department.ResponseSLASampleCount != 1 || department.ResponseSLABreaches != 0 || department.ResolutionSLABreaches != 1 {
		t.Fatalf("unexpected SLA counts: %+v", department)
	}

	if math.Abs(department.AverageResponseSLADeviationSeconds+60) > 1 || math.Abs(department.AverageResolutionSLADeviationSeconds-120) > 1 {
		t.Fatalf("unexpected SLA deviations: %+v", department)
	}

}
