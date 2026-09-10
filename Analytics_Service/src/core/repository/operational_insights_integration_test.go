//go:build integration

package repository

import (
	"context"
	"math"
	"os"
	"testing"
	"time"

	"analytics/models"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

func TestOperationalInsightsInClickHouse(t *testing.T) {
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
		t.Fatalf("clickhouse.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repository := NewAnalyticsRepoStruct(db)
	departmentID := uuid.NewString()
	brigadeID := uuid.NewString()
	ticketAssigned := uuid.NewString()
	ticketQueued := uuid.NewString()
	ticketRepeated := uuid.NewString()
	assetID := uuid.NewString()
	routeID := uuid.NewString()
	shiftID := uuid.NewString()
	start := time.Now().UTC().Add(-20 * time.Minute).Truncate(time.Millisecond)

	events := []models.Event{
		analyticsEvent(ticketAssigned, "ticket.created", start, map[string]any{"ticket_id": ticketAssigned, "department_id": departmentID, "asset_id": assetID, "status": "NEW"}),
		analyticsEvent(ticketAssigned, "ticket.assigned", start.Add(time.Minute), map[string]any{"ticket_id": ticketAssigned, "department_id": departmentID, "brigade_id": brigadeID, "status": "ASSIGNED"}),
		analyticsEvent(ticketAssigned, "ticket.status_changed", start.Add(4*time.Minute), map[string]any{"ticket_id": ticketAssigned, "department_id": departmentID, "brigade_id": brigadeID, "status": "IN_PROGRESS"}),
		analyticsEvent(ticketAssigned, "ticket.completed", start.Add(10*time.Minute), map[string]any{"ticket_id": ticketAssigned, "department_id": departmentID, "brigade_id": brigadeID, "status": "DONE"}),
		analyticsEvent(ticketQueued, "ticket.created", start.Add(2*time.Minute), map[string]any{"ticket_id": ticketQueued, "department_id": departmentID, "status": "NEW"}),
		analyticsEvent(ticketRepeated, "ticket.created", start.Add(time.Minute), map[string]any{"ticket_id": ticketRepeated, "department_id": departmentID, "asset_id": assetID, "status": "NEW"}),
		analyticsEvent(ticketRepeated, "ticket.assigned", start.Add(2*time.Minute), map[string]any{"ticket_id": ticketRepeated, "department_id": departmentID, "asset_id": assetID, "brigade_id": brigadeID, "status": "ASSIGNED"}),
		analyticsEvent(ticketRepeated, "ticket.status_changed", start.Add(3*time.Minute), map[string]any{"ticket_id": ticketRepeated, "department_id": departmentID, "asset_id": assetID, "brigade_id": brigadeID, "status": "IN_PROGRESS"}),
		analyticsEvent(ticketRepeated, "ticket.completed", start.Add(8*time.Minute), map[string]any{"ticket_id": ticketRepeated, "department_id": departmentID, "asset_id": assetID, "brigade_id": brigadeID, "status": "DONE"}),
		analyticsEvent(routeID, "routing.route.created.v1", start.Add(2*time.Minute), map[string]any{"id": routeID, "ticket_id": ticketAssigned, "brigade_id": brigadeID, "status": "PLANNED", "revision": 0, "distance_meters": 12000.0, "duration_seconds": 900.0, "destination": map[string]any{"latitude": 55.75, "longitude": 37.61}}),
		analyticsEvent(routeID, "routing.route.recalculated.v1", start.Add(3*time.Minute), map[string]any{"id": routeID, "ticket_id": ticketAssigned, "brigade_id": brigadeID, "status": "PLANNED", "revision": 1, "distance_meters": 10000.0, "duration_seconds": 800.0, "destination": map[string]any{"latitude": 55.75, "longitude": 37.61}}),
		analyticsEvent(shiftID, "BrigadeShiftStarted", start, map[string]any{"shift_id": shiftID, "brigade_id": brigadeID, "department_id": departmentID}),
		analyticsEvent(shiftID, "BrigadeShiftEnded", start.Add(15*time.Minute), map[string]any{"shift_id": shiftID, "brigade_id": brigadeID, "department_id": departmentID}),
	}
	positionEvent := models.Event{
		ID: uuid.NewString(), Type: "VehiclePositionUpdated", Topic: "locations.events.v1",
		Payload:   map[string]any{"brigade_id": brigadeID, "speed_kmh": "12.5", "accuracy_meters": "8", "occurred_at": start.Add(2 * time.Minute).Format(time.RFC3339Nano)},
		Timestamp: start.Add(2 * time.Minute), Version: 1, ProjectionEligible: true,
	}
	arrivalEvent := models.Event{
		ID: uuid.NewString(), Type: "VehiclePositionUpdated", Topic: "locations.events.v1",
		Payload:   map[string]any{"brigade_id": brigadeID, "latitude": "55.7501", "longitude": "37.6101", "speed_kmh": "0", "accuracy_meters": "8", "occurred_at": start.Add(14 * time.Minute).Format(time.RFC3339Nano)},
		Timestamp: start.Add(14 * time.Minute), Version: 1, ProjectionEligible: true,
	}
	slaEvent := models.Event{
		ID: uuid.NewString(), Type: "SLA_RESOLUTION_BREACHED", Topic: "sla.events.v1",
		Payload:   map[string]any{"ticket_id": ticketAssigned, "occurred_at": start.Add(9 * time.Minute).Format(time.RFC3339Nano)},
		Timestamp: start.Add(9 * time.Minute), Version: 1, ProjectionEligible: true,
	}
	events = append(events, positionEvent, arrivalEvent, slaEvent)
	for _, event := range events {
		if err = repository.Store(ctx, event); err != nil {
			t.Fatalf("Store(%s) error = %v", event.Type, err)
		}
	}
	t.Cleanup(func() {
		_ = db.Exec(context.Background(), "DELETE FROM domain_events WHERE department_id=? OR event_id IN (?,?,?,?,?)", departmentID, events[9].ID, events[10].ID, positionEvent.ID, arrivalEvent.ID, slaEvent.ID)
		_ = db.Exec(context.Background(), "DELETE FROM domain_events_projection_v1 WHERE department_id=? OR event_id IN (?,?,?,?,?)", departmentID, events[9].ID, events[10].ID, positionEvent.ID, arrivalEvent.ID, slaEvent.ID)
	})
	from := start.Add(-time.Second)
	to := start.Add(15 * time.Minute)
	insights, err := repository.OperationalInsights(ctx, models.Filter{From: &from, To: &to, DepartmentID: &departmentID})
	if err != nil {
		t.Fatalf("OperationalInsights() error = %v", err)
	}
	if insights.DepartureTime.SampleCount != 2 || insights.DepartureTime.AverageSeconds != 60 {
		t.Errorf("DepartureTime = %+v, want two assigned tickets departing after 60 seconds", insights.DepartureTime)
	}
	if insights.QueueAge.ActiveUnassigned != 1 || math.Abs(insights.QueueAge.Age.AverageSeconds-780) > 0.001 {
		t.Errorf("QueueAge = %+v, want one 780-second item", insights.QueueAge)
	}
	if insights.Routing.Routes != 1 || insights.Routing.Recalculations != 1 || insights.Routing.AverageDistanceKM != 10 || insights.Routing.KilometersPerCompletedTicket != 10 {
		t.Errorf("Routing = %+v, want one route, one recalculation and 10 km", insights.Routing)
	}
	if insights.Routing.ETASampleCount != 1 || insights.Routing.ETAMeanAbsoluteErrorSeconds != 140 || insights.Routing.ETABiasSeconds != -140 || insights.Routing.ETAWithinFiveMinutesRate != 100 {
		t.Errorf("Routing ETA = %+v, want one sample with -140 second error within five minutes", insights.Routing)
	}
	if insights.CapacityForecast.ObservedDays != 1 || insights.CapacityForecast.ForecastNextDay != 3 {
		t.Errorf("CapacityForecast = %+v, want one observed day and forecast 3", insights.CapacityForecast)
	}
	performance, err := repository.BrigadePerformance(ctx, models.Filter{From: &from, To: &to, DepartmentID: &departmentID})
	if err != nil {
		t.Fatalf("BrigadePerformance() error = %v", err)
	}
	if performance.Completed != 2 || performance.ExecutionTime.AverageSeconds != 330 || performance.RepeatedAssetTickets != 1 {
		t.Errorf("BrigadePerformance() = %+v, want completed=2 average=330 repeated=1", performance)
	}
	if performance.SLABreaches != 1 || performance.SLABreachRate != 50 || !performance.ShiftMetricsAvailable {
		t.Errorf("BrigadePerformance SLA/shift = %+v, want one breach, 50%% and shift metrics", performance)
	}
	if performance.ShiftCount != 1 || math.Abs(performance.ShiftHours-0.25) > 0.001 || performance.CompletedPerShift != 2 || math.Abs(performance.UtilizationRate-73.333333) > 0.001 {
		t.Errorf("BrigadePerformance shifts = %+v, want one 15-minute shift, 2 completed/shift and 73.33%% utilization", performance)
	}
}
