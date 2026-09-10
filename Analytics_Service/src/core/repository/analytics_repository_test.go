package repository

import (
	"math"
	"strings"
	"testing"
	"time"

	"analytics/models"
)

func TestApplyWorkloadBalance(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                   string
		active                 []uint64
		average, deviation, cv float64
		gini                   float64
		max                    uint64
	}{
		{name: "empty"},
		{name: "all idle", active: []uint64{0, 0}},
		{name: "equal", active: []uint64{2, 2}, average: 2, max: 2},
		{name: "idle and overloaded", active: []uint64{0, 2}, average: 1, deviation: 1, cv: 1, gini: 0.5, max: 2},
		{name: "distributed", active: []uint64{1, 2, 3}, average: 2, deviation: math.Sqrt(2.0 / 3.0), cv: math.Sqrt(2.0/3.0) / 2, gini: 2.0 / 9.0, max: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			items := make([]models.BrigadeWorkloadItem, len(test.active))
			for index, active := range test.active {
				items[index] = models.BrigadeWorkloadItem{BrigadeID: string(rune('a' + index)), Active: active}
			}
			result := models.BrigadeWorkload{Brigades: items}
			applyWorkloadBalance(&result)
			if result.BrigadeCount != uint64(len(test.active)) || result.MaxActive != test.max {
				t.Errorf("counts = (%d, %d), want (%d, %d)", result.BrigadeCount, result.MaxActive, len(test.active), test.max)
			}
			assertClose(t, "average", result.AverageActive, test.average)
			assertClose(t, "standard deviation", result.StandardDeviation, test.deviation)
			assertClose(t, "coefficient of variation", result.CoefficientOfVariation, test.cv)
			assertClose(t, "gini", result.Gini, test.gini)
		})
	}
}

func TestMergeEligibleBrigadesAddsIdleAndSorts(t *testing.T) {
	t.Parallel()
	items := []models.BrigadeWorkloadItem{{BrigadeID: "brigade-b", Active: 2}}
	got := mergeEligibleBrigades(items, []string{"brigade-c", "brigade-a", "brigade-b"})
	if len(got) != 3 || got[0].BrigadeID != "brigade-a" || got[1].Active != 2 || got[2].BrigadeID != "brigade-c" {
		t.Fatalf("mergeEligibleBrigades() = %+v, want sorted entries including idle brigades", got)
	}
}

func TestApplyShiftMetrics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		performance     models.BrigadePerformance
		shift           brigadeShiftMetric
		completed       float64
		busyHours       float64
		parallel        float64
		utilizationRate float64
	}{
		{name: "no shifts", performance: models.BrigadePerformance{Completed: 3}},
		{
			name: "one shift", performance: models.BrigadePerformance{Completed: 2, ExecutionTime: models.LatencyDistribution{SampleCount: 2, AverageSeconds: 330}},
			shift: brigadeShiftMetric{ShiftCount: 1, ShiftHours: 0.25}, completed: 2,
			busyHours: 660.0 / 3600, parallel: 660.0 / 900, utilizationRate: 660.0 / 900 * 100,
		},
		{
			name: "parallel work caps utilization", performance: models.BrigadePerformance{Completed: 4, ExecutionTime: models.LatencyDistribution{SampleCount: 4, AverageSeconds: 1800}},
			shift: brigadeShiftMetric{ShiftCount: 2, ShiftHours: 1}, completed: 2,
			busyHours: 2, parallel: 2, utilizationRate: 100,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.performance
			applyShiftMetrics(&result, test.shift)
			assertClose(t, "completed per shift", result.CompletedPerShift, test.completed)
			assertClose(t, "busy hours", result.BusyHours, test.busyHours)
			assertClose(t, "average parallel tasks", result.AverageParallelTasks, test.parallel)
			assertClose(t, "utilization", result.UtilizationRate, test.utilizationRate)
		})
	}
}

func assertClose(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("%s = %f, want %f", name, got, want)
	}
}

func TestEventTimeUsesEnvelopeTimestampForEntityEvents(t *testing.T) {
	envelope := time.Date(2026, 8, 17, 9, 30, 0, 0, time.UTC)
	got := eventTime(models.Event{
		Timestamp: envelope,
		Payload: map[string]any{
			"created_at": "2026-08-16T08:00:00Z",
			"updated_at": "2026-08-17T09:00:00Z",
		},
	})
	if !got.Equal(envelope) {
		t.Fatalf("eventTime() = %v, want envelope timestamp %v", got, envelope)
	}
}

func TestOperationalFiltersAreAppliedAfterLifecycleAggregation(t *testing.T) {
	t.Parallel()
	departmentID := "department-1"
	mode := "automatic"
	filter := models.Filter{
		DepartmentID:   &departmentID,
		AssignmentMode: &mode,
	}
	where, args := buildAssignmentDimensions(filter)
	if !strings.Contains(where, "department_id=?") || !strings.Contains(where, "assignment_mode=?") {
		t.Errorf("buildAssignmentDimensions(%+v) = %q, want department and mode filters", filter, where)
	}
	if len(args) != 2 || args[0] != departmentID || args[1] != "AUTOMATIC" {
		t.Errorf("buildAssignmentDimensions(%+v) args = %#v, want [%q %q]", filter, args, departmentID, "AUTOMATIC")
	}
}

func TestEventTimeUsesExplicitOccurredAt(t *testing.T) {
	envelope := time.Date(2026, 8, 17, 9, 30, 0, 0, time.UTC)
	want := time.Date(2026, 8, 17, 9, 15, 0, 0, time.UTC)
	got := eventTime(models.Event{
		Timestamp: envelope,
		Payload:   map[string]any{"occurred_at": want.Format(time.RFC3339Nano)},
	})
	if !got.Equal(want) {
		t.Fatalf("eventTime() = %v, want explicit occurrence time %v", got, want)
	}
}

func TestPayloadValuesIgnoreCaseAndEnvelopeShape(t *testing.T) {
	t.Parallel()
	payload := map[string]any{
		"Data": map[string]any{
			"CalculationDurationMs": 1250.0,
			"FailureStage":          "candidate_ranking",
			"Trace-ID":              "trace-42",
			"SUCCESS":               true,
		},
	}
	if got := stringValue(payload, "trace_id"); got != "trace-42" {
		t.Errorf("stringValue(payload, trace_id) = %q, want %q", got, "trace-42")
	}
	if got := numberValue(payload, "calculation_duration_ms"); got == nil || *got != 1250 {
		t.Errorf("numberValue(payload, calculation_duration_ms) = %v, want 1250", got)
	}
	if got := boolValue(payload, "success"); got == nil || !*got {
		t.Errorf("boolValue(payload, success) = %v, want true", got)
	}
	if got := stringValue(payload, "failure_stage"); got != "candidate_ranking" {
		t.Errorf("stringValue(payload, failure_stage) = %q, want %q", got, "candidate_ranking")
	}
}

func TestCrossServicePayloadContract(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		payload map[string]any
		fields  map[string]string
	}{
		{
			name:    "dispatch snake case",
			payload: map[string]any{"operation_id": "operation-1", "ticket_id": "ticket-1", "department_id": "department-1", "failure_stage": "ROUTING"},
			fields:  map[string]string{"aggregate_id": "operation-1", "ticket_id": "ticket-1", "department_id": "department-1", "failure_stage": "ROUTING"},
		},
		{
			name:    "routing camel case",
			payload: map[string]any{"TicketId": "ticket-2", "Route-ID": "route-2", "FailureCode": "ENGINE_TIMEOUT"},
			fields:  map[string]string{"ticket_id": "ticket-2", "route_id": "route-2", "failure_code": "ENGINE_TIMEOUT"},
		},
		{
			name:    "brigade nested data",
			payload: map[string]any{"Data": map[string]any{"BrigadeID": "brigade-3", "UserId": "user-3", "AvailabilityStatus": "AVAILABLE"}},
			fields:  map[string]string{"brigade_id": "brigade-3", "user_id": "user-3", "availability_status": "AVAILABLE"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for field, want := range test.fields {
				keys := []string{field}
				if field == "aggregate_id" {
					keys = []string{"aggregate_id", "operation_id"}
				}
				if got := stringValue(test.payload, keys...); got != want {
					t.Errorf("stringValue(%s, %q) = %q, want %q", test.name, field, got, want)
				}
			}
		})
	}
}

func TestPublishedEventTypeFixtures(t *testing.T) {
	t.Parallel()
	dispatchTypes := []string{
		"dispatch.requested", "dispatch.candidates_ranked", "dispatch.reserved", "dispatch.route_built",
		"dispatch.assigned", "dispatch.failed", "dispatch.expired", "dispatch.canceled",
	}
	for _, eventType := range dispatchTypes {
		t.Run(eventType, func(t *testing.T) {
			payload := map[string]any{
				"event_id": "event-1", "event_type": eventType, "event_version": float64(1),
				"producer": "dispatch-service", "operation_id": "operation-1", "ticket_id": "ticket-1",
				"department_id": "department-1", "category_id": "category-1", "priority": "HIGH",
				"brigade_id": "brigade-1", "route_id": "route-1", "mode": "AUTOMATIC",
				"failure_code": "NO_ROUTE", "failure_stage": "ROUTING", "trace_id": "trace-1",
				"candidate_count": float64(4), "reachable_candidate_count": float64(2),
			}
			assertStringFields(t, payload, map[string]string{
				"event_id": "event-1", "event_type": eventType, "operation_id": "operation-1",
				"ticket_id": "ticket-1", "department_id": "department-1", "category_id": "category-1",
				"priority": "HIGH", "brigade_id": "brigade-1", "route_id": "route-1",
				"mode": "AUTOMATIC", "failure_code": "NO_ROUTE", "failure_stage": "ROUTING", "trace_id": "trace-1",
			})
			if got := uint64Value(payload, "candidate_count"); got == nil || *got != 4 {
				t.Errorf("candidate_count = %v, want 4", got)
			}
		})
	}

	for _, eventType := range []string{"routing.route.created.v1", "routing.route.recalculated.v1", "routing.route.status_changed.v1", "routing.calculation.failed.v1"} {
		t.Run(eventType, func(t *testing.T) {
			payload := map[string]any{
				"event_type": eventType, "id": "route-1", "ticket_id": "ticket-1", "brigade_id": "brigade-1",
				"calculation_duration_ms": float64(125), "distance_meters": float64(5000),
				"duration_seconds": float64(600), "success": eventType != "routing.calculation.failed.v1",
				"engine": "valhalla", "travel_mode": "auto", "failure_code": "NO_ROUTE",
			}
			if got := eventRouteID(models.Event{Topic: "routing.events.v1", Payload: payload}); got != "route-1" {
				t.Errorf("route id = %q, want route-1", got)
			}
			assertStringFields(t, payload, map[string]string{"ticket_id": "ticket-1", "brigade_id": "brigade-1", "engine": "valhalla", "travel_mode": "auto"})
			if got := numberValue(payload, "calculation_duration_ms"); got == nil || *got != 125 {
				t.Errorf("calculation_duration_ms = %v, want 125", got)
			}
		})
	}

	for _, eventType := range []string{
		"BrigadeCreated", "BrigadeUpdated", "BrigadeStatusChanged", "BrigadeDeactivated", "BrigadeArchived",
		"BrigadeMemberAdded", "BrigadeMemberRemoved", "BrigadeMemberAvailabilityChanged", "BrigadeMemberRoleChanged",
		"BrigadeScheduleChanged", "BrigadeSkillAdded", "BrigadeSkillRemoved",
		"BrigadeZoneCreated", "BrigadeZoneUpdated", "BrigadeZoneDeleted", "BrigadeShiftStarted", "BrigadeShiftEnded",
	} {
		t.Run(eventType, func(t *testing.T) {
			payload := map[string]any{
				"event_type": eventType, "brigade_id": "brigade-1", "department_id": "department-1",
				"member_id": "member-1", "user_id": "user-1", "shift_id": "shift-1",
				"member_status": "ACTIVE", "availability_status": "AVAILABLE", "role": "DRIVER",
			}
			assertStringFields(t, payload, map[string]string{
				"brigade_id": "brigade-1", "department_id": "department-1", "member_id": "member-1",
				"user_id": "user-1", "shift_id": "shift-1", "member_status": "ACTIVE",
				"availability_status": "AVAILABLE", "role": "DRIVER",
			})
		})
	}
}

func assertStringFields(t *testing.T, payload map[string]any, fields map[string]string) {
	t.Helper()
	for field, want := range fields {
		if got := stringValue(payload, field); got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
	}
}

func TestOperationalLatencyGroupDimensions(t *testing.T) {
	t.Parallel()
	assignment := []string{"DEPARTMENT", "CATEGORY", "PRIORITY", "ASSIGNMENT_MODE", "BRIGADE"}
	for _, dimension := range assignment {
		if _, ok := assignmentGroupColumn(dimension); !ok {
			t.Errorf("assignmentGroupColumn(%q) ok = false, want true", dimension)
		}
	}
	routing := []string{"DEPARTMENT", "CATEGORY", "PRIORITY", "ASSIGNMENT_MODE", "BRIGADE", "ENGINE", "TRAVEL_MODE", "SUCCESS", "FAILURE_CODE"}
	for _, dimension := range routing {
		if _, ok := routingGroupExpression(dimension); !ok {
			t.Errorf("routingGroupExpression(%q) ok = false, want true", dimension)
		}
	}
	if _, ok := assignmentGroupColumn("ENGINE"); ok {
		t.Error("assignmentGroupColumn(ENGINE) ok = true, want false")
	}
	if _, ok := routingGroupExpression("INVALID"); ok {
		t.Error("routingGroupExpression(INVALID) ok = true, want false")
	}
}

func TestRoutingPayloadFields(t *testing.T) {
	t.Parallel()
	payload := map[string]any{
		"id":          "route-1",
		"revision":    float64(2),
		"destination": map[string]any{"latitude": 55.75, "longitude": 37.61},
		"calculation": map[string]any{
			"summary": map[string]any{
				"distance_meters":  12500.0,
				"duration_seconds": 900.0,
			},
		},
	}
	if got := eventRouteID(models.Event{Topic: "routing.events.v1", Payload: payload}); got != "route-1" {
		t.Errorf("eventRouteID(routing event) = %q, want route-1", got)
	}
	if got := stringValue(payload, "id"); got != "route-1" {
		t.Errorf("stringValue(payload, id) = %q, want route-1", got)
	}
	if got := uint64Value(payload, "revision"); got == nil || *got != 2 {
		t.Errorf("uint64Value(payload, revision) = %v, want 2", got)
	}
	if got := numberValue(payload, "distance_meters"); got == nil || *got != 12500 {
		t.Errorf("numberValue(payload, distance_meters) = %v, want 12500", got)
	}
	if got := numberValue(payload, "duration_seconds"); got == nil || *got != 900 {
		t.Errorf("numberValue(payload, duration_seconds) = %v, want 900", got)
	}
	if got := numberPathValue(payload, "destination", "latitude"); got == nil || *got != 55.75 {
		t.Errorf("numberPathValue(payload, destination, latitude) = %v, want 55.75", got)
	}
}

func TestEventEntityIDUsesTopicAggregate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, topic, want string
		payload           map[string]any
	}{
		{name: "brigade does not collapse into department", topic: "brigades.events.v1", payload: map[string]any{"department_id": "department-1", "brigade_id": "brigade-1"}, want: "brigade-1"},
		{name: "dispatch operation", topic: "dispatch.events.v1", payload: map[string]any{"ticket_id": "ticket-1", "operation_id": "operation-1"}, want: "operation-1"},
		{name: "ticket", topic: "tickets.events.v1", payload: map[string]any{"department_id": "department-1", "ticket_id": "ticket-1"}, want: "ticket-1"},
		{name: "explicit aggregate wins", topic: "brigades.events.v1", payload: map[string]any{"aggregate_id": "aggregate-1", "brigade_id": "brigade-1"}, want: "aggregate-1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := eventEntityID(models.Event{Topic: test.topic, Payload: test.payload}); got != test.want {
				t.Errorf("eventEntityID() = %q, want %q", got, test.want)
			}
		})
	}
}
