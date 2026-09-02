//go:build integration

package repository

import (
	"context"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"analytics/models"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

func TestOperationalLatencyGroupsInClickHouse(t *testing.T) {
	address := os.Getenv("CLICKHOUSE_TEST_ADDR")
	if address == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR is not set")
	}
	ctx := context.Background()
	db, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{address},
		Auth: clickhouse.Auth{
			Database: "analytics",
			Username: "analytics",
			Password: os.Getenv("CLICKHOUSE_TEST_PASSWORD"),
		},
	})
	if err != nil {
		t.Fatalf("clickhouse.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = db.Ping(ctx); err != nil {
		t.Fatalf("ClickHouse Ping() error = %v", err)
	}

	repository := NewAnalyticsRepoStruct(db)
	ticketID := uuid.NewString()
	departmentID := uuid.NewString()
	start := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	events := []models.Event{
		analyticsEvent(ticketID, "dispatch.requested", start, map[string]any{
			"operation_id": uuid.NewString(), "ticket_id": ticketID, "department_id": departmentID,
			"priority": "EMERGENCY", "mode": "AUTOMATIC",
		}),
		analyticsEvent(ticketID, "dispatch.assigned", start.Add(12*time.Second), map[string]any{
			"ticket_id": ticketID, "department_id": departmentID, "priority": "EMERGENCY", "mode": "AUTOMATIC",
		}),
		analyticsEvent(ticketID, "routing.route.created.v1", start.Add(5*time.Second), map[string]any{
			"ticket_id": ticketID, "department_id": departmentID, "priority": "EMERGENCY", "engine": "valhalla",
			"travel_mode": "auto", "success": true, "calculation_duration_ms": 250.0,
		}),
	}
	for _, event := range events {
		if err = repository.Store(ctx, event); err != nil {
			t.Fatalf("Store(%s) error = %v", event.Type, err)
		}
	}
	t.Cleanup(func() {
		_ = db.Exec(context.Background(), "DELETE FROM domain_events WHERE ticket_id=?", ticketID)
		_ = db.Exec(context.Background(), "DELETE FROM domain_events_projection_v1 WHERE ticket_id=?", ticketID)
	})

	filter := models.Filter{DepartmentID: &departmentID}
	byPriority, err := repository.OperationalLatency(ctx, filter, "PRIORITY")
	if err != nil {
		t.Fatalf("OperationalLatency(PRIORITY) error = %v", err)
	}
	priorityGroup := latencyGroup(byPriority.Groups, "EMERGENCY")
	if priorityGroup == nil || priorityGroup.AssignmentTime.SampleCount != 1 || priorityGroup.RoutingCalculationTime.SampleCount != 1 {
		t.Errorf("OperationalLatency(PRIORITY) group = %+v, want one assignment and routing sample", priorityGroup)
	}
	byEngine, err := repository.OperationalLatency(ctx, filter, "ENGINE")
	if err != nil {
		t.Fatalf("OperationalLatency(ENGINE) error = %v", err)
	}
	engineGroup := latencyGroup(byEngine.Groups, "valhalla")
	if engineGroup == nil || engineGroup.AssignmentTime.SampleCount != 0 || engineGroup.RoutingCalculationTime.SampleCount != 1 {
		t.Errorf("OperationalLatency(ENGINE) group = %+v, want only one routing sample", engineGroup)
	}
}

func TestDispatchFailureSummaryInClickHouse(t *testing.T) {
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
	if err = db.Ping(ctx); err != nil {
		t.Fatalf("ClickHouse Ping() error = %v", err)
	}

	repository := NewAnalyticsRepoStruct(db)
	departmentID := uuid.NewString()
	start := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	terminal := []struct {
		status   string
		stage    string
		code     string
		category string
	}{
		{status: "FAILED", stage: "ROUTING", code: "ENGINE_TIMEOUT", category: uuid.NewString()},
		{status: "EXPIRED", stage: "RESERVATION", code: "RESERVATION_EXPIRED", category: uuid.NewString()},
		{status: "FAILED", stage: "CANDIDATE_SELECTION", code: "NO_REACHABLE_BRIGADE", category: uuid.NewString()},
		{status: "CANCELED", stage: "USER_CANCELLATION", code: "USER_REQUEST", category: uuid.NewString()},
	}
	for index, outcome := range terminal {
		operationID := uuid.NewString()
		ticketID := uuid.NewString()
		requested := analyticsEvent(ticketID, "dispatch.requested", start.Add(time.Duration(index)*time.Second), map[string]any{
			"operation_id": operationID, "ticket_id": ticketID, "department_id": departmentID, "category_id": outcome.category,
			"priority": "EMERGENCY", "mode": "AUTOMATIC", "status": "PENDING",
		})
		finished := analyticsEvent(ticketID, "dispatch."+strings.ToLower(outcome.status), start.Add(time.Duration(index+10)*time.Second), map[string]any{
			"operation_id": operationID, "ticket_id": ticketID, "department_id": departmentID, "category_id": outcome.category,
			"priority": "EMERGENCY", "mode": "AUTOMATIC", "status": outcome.status,
			"failure_stage": outcome.stage, "failure_code": outcome.code,
		})
		for _, event := range []models.Event{requested, finished} {
			if err = repository.Store(ctx, event); err != nil {
				t.Fatalf("Store(%s) error = %v", event.Type, err)
			}
		}
	}
	t.Cleanup(func() {
		_ = db.Exec(context.Background(), "DELETE FROM domain_events WHERE department_id=?", departmentID)
		_ = db.Exec(context.Background(), "DELETE FROM domain_events_projection_v1 WHERE department_id=?", departmentID)
	})

	filter := models.Filter{DepartmentID: &departmentID}
	summary, err := repository.DispatchFailures(ctx, filter)
	if err != nil {
		t.Fatalf("DispatchFailures() error = %v", err)
	}
	if summary.Requested != 4 || summary.Failed != 2 || summary.Expired != 1 || summary.Canceled != 1 || summary.FailureRate != 100 {
		t.Errorf("DispatchFailures() = %+v, want four unsuccessful requested operations", summary)
	}
	if item := failureBreakdown(summary.ByStage, "ROUTING"); item == nil || item.Count != 1 {
		t.Errorf("ByStage ROUTING = %+v, want count 1", item)
	}
	if item := failureBreakdown(summary.ByCode, "ENGINE_TIMEOUT"); item == nil || item.Count != 1 {
		t.Errorf("ByCode ENGINE_TIMEOUT = %+v, want count 1", item)
	}
	for _, reason := range []string{"NO_SUITABLE_BRIGADE", "NO_ROUTE", "RESERVATION_EXPIRED"} {
		if item := failureReason(summary.BusinessReasons, reason); item == nil || item.Count != 1 || item.RequestRate != 25 {
			t.Errorf("BusinessReasons %s = %+v, want count 1 and request rate 25", reason, item)
		}
		if item := failureReasonDimension(summary.ReasonsByDepartment, reason, departmentID); item == nil || item.Count != 1 || item.ReasonPercent != 100 {
			t.Errorf("ReasonsByDepartment(%s, %s) = %+v, want count 1 and reason percent 100", reason, departmentID, item)
		}
	}
}

func TestBrigadeWorkloadInClickHouse(t *testing.T) {
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
	if err = db.Ping(ctx); err != nil {
		t.Fatalf("ClickHouse Ping() error = %v", err)
	}

	repository := NewAnalyticsRepoStruct(db)
	departmentID := uuid.NewString()
	brigadeOne := uuid.NewString()
	brigadeTwo := uuid.NewString()
	brigadeIdle := uuid.NewString()
	start := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	for _, brigadeID := range []string{brigadeOne, brigadeTwo, brigadeIdle} {
		if err = repository.Store(ctx, analyticsEvent(brigadeID, "BrigadeCreated", start.Add(-time.Second), map[string]any{
			"brigade_id": brigadeID, "department_id": departmentID, "status": "ACTIVE",
		})); err != nil {
			t.Fatalf("Store(BrigadeCreated) error = %v", err)
		}
	}
	type ticketState struct {
		brigade string
		status  string
	}
	states := []ticketState{
		{brigade: brigadeOne, status: "ASSIGNED"},
		{brigade: brigadeOne, status: "DONE"},
		{status: "NEW"},
		{brigade: brigadeTwo, status: "IN_PROGRESS"},
	}
	for index, state := range states {
		ticketID := uuid.NewString()
		base := map[string]any{"ticket_id": ticketID, "department_id": departmentID, "priority": "HIGH", "status": "NEW"}
		if err = repository.Store(ctx, analyticsEvent(ticketID, "ticket.created", start.Add(time.Duration(index)*time.Second), base)); err != nil {
			t.Fatalf("Store(ticket.created) error = %v", err)
		}
		if state.brigade == "" {
			continue
		}
		assignedAt := start.Add(time.Duration(index+10) * time.Second)
		if err = repository.Store(ctx, analyticsEvent(ticketID, "ticket.assigned", assignedAt, map[string]any{
			"ticket_id": ticketID, "department_id": departmentID, "brigade_id": state.brigade, "priority": "HIGH", "status": "ASSIGNED",
		})); err != nil {
			t.Fatalf("Store(ticket.assigned) error = %v", err)
		}
		if state.status != "ASSIGNED" {
			eventType := "ticket.status_changed"
			if state.status == "DONE" {
				eventType = "ticket.completed"
			}
			if err = repository.Store(ctx, analyticsEvent(ticketID, eventType, assignedAt.Add(time.Second), map[string]any{
				"ticket_id": ticketID, "department_id": departmentID, "brigade_id": state.brigade, "priority": "HIGH", "status": state.status,
			})); err != nil {
				t.Fatalf("Store(%s) error = %v", eventType, err)
			}
		}
	}
	t.Cleanup(func() {
		_ = db.Exec(context.Background(), "DELETE FROM domain_events WHERE department_id=?", departmentID)
		_ = db.Exec(context.Background(), "DELETE FROM domain_events_projection_v1 WHERE department_id=?", departmentID)
	})
	from := start.Add(-time.Second)
	to := start.Add(time.Minute)
	summary, err := repository.BrigadeWorkload(ctx, models.Filter{From: &from, To: &to, DepartmentID: &departmentID})
	if err != nil {
		t.Fatalf("BrigadeWorkload() error = %v", err)
	}
	if summary.Incoming != 4 || summary.Assigned != 3 || summary.Completed != 1 || summary.Active != 2 || summary.UnassignedBacklog != 1 {
		t.Errorf("BrigadeWorkload() = %+v, want incoming=4 assigned=3 completed=1 active=2 backlog=1", summary)
	}
	if item := workloadItem(summary.Brigades, brigadeOne); item == nil || item.Active != 1 || item.Assigned != 2 || item.Completed != 1 {
		t.Errorf("brigade one workload = %+v, want active=1 assigned=2 completed=1", item)
	}
	if item := workloadItem(summary.Brigades, brigadeIdle); item == nil || item.Active != 0 {
		t.Errorf("idle brigade workload = %+v, want active=0", item)
	}
	if summary.BrigadeCount != 3 || summary.MaxActive != 1 {
		t.Errorf("workload balance counts = (%d, %d), want brigade_count=3 max_active=1", summary.BrigadeCount, summary.MaxActive)
	}
	if math.Abs(summary.AverageActive-2.0/3.0) > 1e-9 || math.Abs(summary.Gini-1.0/3.0) > 1e-9 {
		t.Errorf("workload balance = average %f, gini %f; want 2/3 and 1/3", summary.AverageActive, summary.Gini)
	}
}

func TestActiveWorkersInClickHouse(t *testing.T) {
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
	if err = db.Ping(ctx); err != nil {
		t.Fatalf("ClickHouse Ping() error = %v", err)
	}

	repository := NewAnalyticsRepoStruct(db)
	departmentID := uuid.NewString()
	brigadeID := uuid.NewString()
	start := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	members := []struct {
		availability string
		active       bool
		status       string
	}{
		{availability: "AVAILABLE", active: true, status: "ACTIVE"},
		{availability: "BUSY", active: true, status: "ACTIVE"},
		{availability: "AVAILABLE", active: false, status: "REMOVED"},
	}
	for index, member := range members {
		memberID := uuid.NewString()
		eventType := "BrigadeMemberAdded"
		if member.status == "REMOVED" {
			eventType = "BrigadeMemberRemoved"
		}
		event := analyticsEvent("", eventType, start.Add(time.Duration(index)*time.Second), map[string]any{
			"member_id": memberID, "user_id": uuid.NewString(), "brigade_id": brigadeID,
			"department_id": departmentID, "member_status": member.status,
			"availability_status": member.availability, "active": member.active, "role": "MEMBER",
		})
		if err = repository.Store(ctx, event); err != nil {
			t.Fatalf("Store(%s) error = %v", eventType, err)
		}
	}
	shiftID := uuid.NewString()
	if err = repository.Store(ctx, analyticsEvent(shiftID, "BrigadeShiftStarted", start.Add(-time.Second), map[string]any{
		"shift_id": shiftID, "brigade_id": brigadeID, "department_id": departmentID,
	})); err != nil {
		t.Fatalf("Store(BrigadeShiftStarted) error = %v", err)
	}
	t.Cleanup(func() {
		_ = db.Exec(context.Background(), "DELETE FROM domain_events WHERE department_id=?", departmentID)
		_ = db.Exec(context.Background(), "DELETE FROM domain_events_projection_v1 WHERE department_id=?", departmentID)
	})

	result, err := repository.ActiveWorkers(ctx, models.Filter{DepartmentID: &departmentID})
	if err != nil {
		t.Fatalf("ActiveWorkers() error = %v", err)
	}
	if result.ActiveMembers != 2 || result.Available != 1 || result.OnShift != 2 {
		t.Errorf("ActiveWorkers() = %+v, want 1/2 available and both on shift", result)
	}
	if group := activeWorkerGroup(result.ByBrigade, brigadeID); group == nil || group.ActiveMembers != 2 || group.Available != 1 || group.OnShift != 2 {
		t.Errorf("brigade active workers = %+v, want 1/2 available and both on shift", group)
	}
}

func TestAssignmentFunnelInClickHouse(t *testing.T) {
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
	if err = db.Ping(ctx); err != nil {
		t.Fatalf("ClickHouse Ping() error = %v", err)
	}

	repository := NewAnalyticsRepoStruct(db)
	departmentID := uuid.NewString()
	start := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	stageTypes := [][]struct {
		typeName       string
		candidateCount int
	}{
		{{"dispatch.requested", 0}, {"dispatch.candidates_ranked", 3}, {"dispatch.reserved", 0}, {"dispatch.route_built", 0}, {"dispatch.assigned", 0}},
		{{"dispatch.requested", 0}, {"dispatch.candidates_ranked", 0}},
		{{"dispatch.requested", 0}, {"dispatch.candidates_ranked", 2}},
	}
	for operationIndex, operation := range stageTypes {
		operationID := uuid.NewString()
		ticketID := uuid.NewString()
		for stageIndex, stage := range operation {
			payload := map[string]any{
				"operation_id": operationID, "ticket_id": ticketID, "department_id": departmentID,
				"priority": "HIGH", "mode": "AUTOMATIC", "candidate_count": stage.candidateCount,
			}
			occurredAt := start.Add(time.Duration(operationIndex*20+stageIndex*2) * time.Second)
			if err = repository.Store(ctx, analyticsEvent(ticketID, stage.typeName, occurredAt, payload)); err != nil {
				t.Fatalf("Store(%s) error = %v", stage.typeName, err)
			}
		}
	}
	t.Cleanup(func() {
		_ = db.Exec(context.Background(), "DELETE FROM domain_events WHERE department_id=?", departmentID)
		_ = db.Exec(context.Background(), "DELETE FROM domain_events_projection_v1 WHERE department_id=?", departmentID)
	})

	result, err := repository.AssignmentFunnel(ctx, models.Filter{DepartmentID: &departmentID})
	if err != nil {
		t.Fatalf("AssignmentFunnel() error = %v", err)
	}
	want := map[string]uint64{"REQUESTED": 3, "CANDIDATES_FOUND": 2, "RESERVED": 1, "ROUTE_BUILT": 1, "ASSIGNED": 1}
	for stageName, count := range want {
		stage := funnelStage(result.Stages, stageName)
		if stage == nil || stage.Count != count {
			t.Errorf("stage %s = %+v, want count %d", stageName, stage, count)
		}
	}
	candidates := funnelStage(result.Stages, "CANDIDATES_FOUND")
	if candidates == nil || candidates.TransitionTime.SampleCount != 2 || candidates.TransitionTime.AverageSeconds != 2 {
		t.Errorf("candidates transition = %+v, want two samples averaging 2 seconds", candidates)
	}
}

func TestDispatchEffectivenessInClickHouse(t *testing.T) {
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
	if err = db.Ping(ctx); err != nil {
		t.Fatalf("ClickHouse Ping() error = %v", err)
	}

	repository := NewAnalyticsRepoStruct(db)
	departmentID := uuid.NewString()
	start := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	operations := []struct {
		mode, terminal string
		delay          time.Duration
	}{
		{mode: "AUTOMATIC", terminal: "ASSIGNED", delay: 4 * time.Second},
		{mode: "AUTOMATIC", terminal: "FAILED", delay: 7 * time.Second},
		{mode: "MANUAL", terminal: "ASSIGNED", delay: 12 * time.Second},
	}
	for index, item := range operations {
		operationID := uuid.NewString()
		ticketID := uuid.NewString()
		requestedAt := start.Add(time.Duration(index) * time.Second)
		for _, event := range []models.Event{
			analyticsEvent(ticketID, "dispatch.requested", requestedAt, map[string]any{
				"operation_id": operationID, "ticket_id": ticketID, "department_id": departmentID,
				"mode": item.mode, "status": "PENDING",
			}),
			analyticsEvent(ticketID, "dispatch."+strings.ToLower(item.terminal), requestedAt.Add(item.delay), map[string]any{
				"operation_id": operationID, "ticket_id": ticketID, "department_id": departmentID,
				"mode": item.mode, "status": item.terminal,
			}),
		} {
			if err = repository.Store(ctx, event); err != nil {
				t.Fatalf("Store(%s) error = %v", event.Type, err)
			}
		}
	}
	t.Cleanup(func() {
		_ = db.Exec(context.Background(), "DELETE FROM domain_events WHERE department_id=?", departmentID)
		_ = db.Exec(context.Background(), "DELETE FROM domain_events_projection_v1 WHERE department_id=?", departmentID)
	})

	result, err := repository.DispatchEffectiveness(ctx, models.Filter{DepartmentID: &departmentID})
	if err != nil {
		t.Fatalf("DispatchEffectiveness() error = %v", err)
	}
	if result.Automatic.Requested != 2 || result.Automatic.Assigned != 1 || result.Automatic.SuccessRate != 50 || result.Automatic.AssignmentTime.SampleCount != 1 {
		t.Errorf("DispatchEffectiveness().Automatic = %+v, want 1/2, 50 percent and one latency sample", result.Automatic)
	}
	if result.Manual.Requested != 1 || result.Manual.Assigned != 1 || result.Manual.SuccessRate != 100 || result.Manual.AssignmentTime.SampleCount != 1 {
		t.Errorf("DispatchEffectiveness().Manual = %+v, want 1/1, 100 percent and one latency sample", result.Manual)
	}
	if result.ManualReassignmentAvailable {
		t.Error("DispatchEffectiveness().ManualReassignmentAvailable = true, want false without ticket.reassigned events")
	}
}

func analyticsEvent(ticketID, eventType string, occurredAt time.Time, payload map[string]any) models.Event {
	payload["occurred_at"] = occurredAt.Format(time.RFC3339Nano)
	return models.Event{
		ID:                 uuid.NewString(),
		Type:               eventType,
		Topic:              eventTopic(eventType),
		Payload:            payload,
		Timestamp:          occurredAt,
		Version:            1,
		ProjectionEligible: true,
	}
}

func eventTopic(eventType string) string {
	if strings.HasPrefix(eventType, "routing.") {
		return "routing.events.v1"
	}
	if strings.HasPrefix(eventType, "ticket.") {
		return "tickets.events.v1"
	}
	if strings.HasPrefix(eventType, "Brigade") {
		return "brigades.events.v1"
	}
	return "dispatch.events.v1"
}

func latencyGroup(groups []models.OperationalLatencyGroup, key string) *models.OperationalLatencyGroup {
	for index := range groups {
		if groups[index].Key == key {
			return &groups[index]
		}
	}
	return nil
}

func failureBreakdown(items []models.DispatchFailureBreakdown, key string) *models.DispatchFailureBreakdown {
	for index := range items {
		if items[index].Key == key {
			return &items[index]
		}
	}
	return nil
}

func failureReason(items []models.DispatchFailureReasonSummary, reason string) *models.DispatchFailureReasonSummary {
	for index := range items {
		if items[index].Reason == reason {
			return &items[index]
		}
	}
	return nil
}

func failureReasonDimension(items []models.DispatchFailureReasonDimension, reason, key string) *models.DispatchFailureReasonDimension {
	for index := range items {
		if items[index].Reason == reason && items[index].Key == key {
			return &items[index]
		}
	}
	return nil
}

func workloadItem(items []models.BrigadeWorkloadItem, brigadeID string) *models.BrigadeWorkloadItem {
	for index := range items {
		if items[index].BrigadeID == brigadeID {
			return &items[index]
		}
	}
	return nil
}

func activeWorkerGroup(items []models.ActiveWorkerGroup, key string) *models.ActiveWorkerGroup {
	for index := range items {
		if items[index].Key == key {
			return &items[index]
		}
	}
	return nil
}

func funnelStage(items []models.AssignmentFunnelStage, stage string) *models.AssignmentFunnelStage {
	for index := range items {
		if items[index].Stage == stage {
			return &items[index]
		}
	}
	return nil
}
