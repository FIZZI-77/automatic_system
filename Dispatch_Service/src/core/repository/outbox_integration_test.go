//go:build integration

package repository

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"dispatch/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOperationLockIsExclusiveAcrossReplicas(t *testing.T) {
	pool := integrationPool(t)
	repository := New(pool, pool)
	operationID := uuid.New()

	releaseFirst, acquired, err := repository.TryOperationLock(t.Context(), operationID)
	if err != nil || !acquired {
		t.Fatalf("Repository.TryOperationLock(first) = (%v, %v), want acquired", acquired, err)
	}
	t.Cleanup(func() { _ = releaseFirst() })
	releaseSecond, acquired, err := repository.TryOperationLock(t.Context(), operationID)
	if err != nil {
		t.Fatalf("Repository.TryOperationLock(second) error = %v", err)
	}
	if acquired {
		_ = releaseSecond()
		t.Fatal("Repository.TryOperationLock(second) acquired = true, want false")
	}
	if err = releaseFirst(); err != nil {
		t.Fatalf("release first operation lock error = %v", err)
	}
	releaseSecond, acquired, err = repository.TryOperationLock(t.Context(), operationID)
	if err != nil || !acquired {
		t.Fatalf("Repository.TryOperationLock(after release) = (%v, %v), want acquired", acquired, err)
	}
	if err = releaseSecond(); err != nil {
		t.Fatalf("release second operation lock error = %v", err)
	}
}

func TestExpireClaimsDisjointBatchesAcrossReplicas(t *testing.T) {
	pool := integrationPool(t)
	repository := New(pool, pool)
	operationIDs := make([]uuid.UUID, 0, 4)
	for range 4 {
		operation := createIntegrationOperation(t, repository, pool, -time.Minute)
		operationIDs = append(operationIDs, operation.ID)
	}

	results := make(chan []*models.Operation, 2)
	errorsChannel := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			items, expireErr := repository.Expire(t.Context(), 2)
			results <- items
			errorsChannel <- expireErr
		}()
	}
	workers.Wait()
	close(results)
	close(errorsChannel)
	for expireErr := range errorsChannel {
		if expireErr != nil {
			t.Fatalf("Repository.Expire(concurrent) error = %v", expireErr)
		}
	}
	seen := make(map[uuid.UUID]struct{}, 4)
	for items := range results {
		for _, item := range items {
			if _, exists := seen[item.ID]; exists {
				t.Errorf("Repository.Expire(concurrent) returned operation %s more than once", item.ID)
			}
			seen[item.ID] = struct{}{}
		}
	}
	if len(seen) != len(operationIDs) {
		t.Errorf("Repository.Expire(concurrent) unique operations = %d, want %d", len(seen), len(operationIDs))
	}
}

func TestCreateAndReserveWriteOutboxInTransaction(t *testing.T) {
	databaseURL := os.Getenv("DISPATCH_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DISPATCH_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	t.Cleanup(pool.Close)

	ticketID := uuid.New()
	departmentID := uuid.New()
	categoryID := uuid.New()
	requestedBy := uuid.New()
	repository := New(pool, pool)
	operation, err := repository.Create(ctx, models.CreateOperationInput{
		TicketID:     ticketID,
		DepartmentID: departmentID,
		CategoryID:   categoryID,
		Priority:     "HIGH",
		RequestedBy:  requestedBy,
		Mode:         models.ModeAutomatic,
		TTL:          time.Minute,
	})
	if err != nil {
		t.Fatalf("Repository.Create() error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM dispatch_outbox_events WHERE aggregate_id=$1", operation.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM dispatch_operations WHERE id=$1", operation.ID)
	})

	assertOutboxEvent(t, pool, operation.ID, "dispatch.requested")
	assertEventDimensions(t, pool, operation.ID, departmentID, categoryID, "HIGH")
	brigadeID := uuid.New()
	reserved, err := repository.SetReserved(ctx, operation.ID, brigadeID, operation.Version)
	if err != nil {
		t.Fatalf("Repository.SetReserved() error = %v", err)
	}
	if reserved.Status != models.StatusReserved || reserved.BrigadeID == nil || *reserved.BrigadeID != brigadeID {
		t.Errorf("Repository.SetReserved() = %+v, want RESERVED for brigade %s", reserved, brigadeID)
	}
	assertOutboxEvent(t, pool, operation.ID, "dispatch.reserved")
	assertEventTimestamp(t, pool, operation.ID, "dispatch.reserved", "reserved_at")
	failed, err := repository.SetFailed(ctx, operation.ID, "ROUTING", "ROUTE_UNAVAILABLE", "route engine unavailable", reserved.Version)
	if err != nil {
		t.Fatalf("Repository.SetFailed() error = %v", err)
	}
	if failed.FailureStage == nil || *failed.FailureStage != "ROUTING" {
		t.Errorf("Repository.SetFailed() failure_stage = %v, want ROUTING", failed.FailureStage)
	}
	assertFailureEvent(t, pool, operation.ID, "ROUTING", "ROUTE_UNAVAILABLE")
}

func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("DISPATCH_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DISPATCH_TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func createIntegrationOperation(t *testing.T, repository *Repository, pool *pgxpool.Pool, ttl time.Duration) *models.Operation {
	t.Helper()
	operation, err := repository.Create(t.Context(), models.CreateOperationInput{
		TicketID: uuid.New(), DepartmentID: uuid.New(), CategoryID: uuid.New(), Priority: "EMERGENCY",
		RequestedBy: uuid.New(), Mode: models.ModeAutomatic, TTL: ttl,
	})
	if err != nil {
		t.Fatalf("Repository.Create(integration operation) error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM dispatch_outbox_events WHERE aggregate_id=$1", operation.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM dispatch_operations WHERE id=$1", operation.ID)
	})
	return operation
}

func TestCreateWithTriggerEventIsIdempotent(t *testing.T) {
	databaseURL := os.Getenv("DISPATCH_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DISPATCH_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	t.Cleanup(pool.Close)
	repository := New(pool, pool)
	triggerEventID := uuid.New()
	input := models.CreateOperationInput{
		TicketID: uuid.New(), DepartmentID: uuid.New(), CategoryID: uuid.New(), Priority: "EMERGENCY",
		RequestedBy: uuid.New(), Mode: models.ModeAutomatic, TTL: time.Minute, TriggerEventID: &triggerEventID,
	}
	first, err := repository.Create(ctx, input)
	if err != nil {
		t.Fatalf("Repository.Create(first trigger) error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM dispatch_outbox_events WHERE aggregate_id=$1", first.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM dispatch_operations WHERE id=$1", first.ID)
	})
	second, err := repository.Create(ctx, input)
	if err != nil {
		t.Fatalf("Repository.Create(duplicate trigger) error = %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("Repository.Create(duplicate trigger) operation = %s, want %s", second.ID, first.ID)
	}
	var requestedEvents int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM dispatch_outbox_events WHERE aggregate_id=$1 AND event_type='dispatch.requested'", first.ID).Scan(&requestedEvents); err != nil {
		t.Fatalf("count dispatch.requested error = %v", err)
	}
	if requestedEvents != 1 {
		t.Errorf("dispatch.requested count = %d, want 1", requestedEvents)
	}
}

func assertFailureEvent(t *testing.T, pool *pgxpool.Pool, aggregateID uuid.UUID, stage, code string) {
	t.Helper()
	var gotStage, gotCode string
	if err := pool.QueryRow(
		context.Background(),
		`SELECT payload->>'failure_stage',payload->>'failure_code' FROM dispatch_outbox_events WHERE aggregate_id=$1 AND event_type='dispatch.failed'`,
		aggregateID,
	).Scan(&gotStage, &gotCode); err != nil {
		t.Fatalf("query dispatch.failed payload error = %v", err)
	}
	if gotStage != stage || gotCode != code {
		t.Errorf("dispatch.failed stage/code = (%q, %q), want (%q, %q)", gotStage, gotCode, stage, code)
	}
}

func assertOutboxEvent(t *testing.T, pool *pgxpool.Pool, aggregateID uuid.UUID, eventType string) {
	t.Helper()
	var count int
	if err := pool.QueryRow(
		context.Background(),
		"SELECT count(*) FROM dispatch_outbox_events WHERE aggregate_id=$1 AND event_type=$2",
		aggregateID,
		eventType,
	).Scan(&count); err != nil {
		t.Fatalf("query outbox event %q error = %v", eventType, err)
	}
	if count != 1 {
		t.Errorf("outbox event %q count = %d, want 1", eventType, count)
	}
}

func assertEventDimensions(t *testing.T, pool *pgxpool.Pool, aggregateID, departmentID, categoryID uuid.UUID, priority string) {
	t.Helper()
	var eventID, payloadEventID, gotDepartmentID, gotCategoryID, gotPriority string
	if err := pool.QueryRow(
		context.Background(),
		`SELECT id::text,payload->>'event_id',payload->>'department_id',payload->>'category_id',payload->>'priority'
		 FROM dispatch_outbox_events WHERE aggregate_id=$1 AND event_type='dispatch.requested'`,
		aggregateID,
	).Scan(&eventID, &payloadEventID, &gotDepartmentID, &gotCategoryID, &gotPriority); err != nil {
		t.Fatalf("query dispatch.requested dimensions error = %v", err)
	}
	if eventID != payloadEventID {
		t.Errorf("dispatch.requested payload event_id = %q, want outbox id %q", payloadEventID, eventID)
	}
	if gotDepartmentID != departmentID.String() || gotCategoryID != categoryID.String() || gotPriority != priority {
		t.Errorf("dispatch.requested dimensions = (%q, %q, %q), want (%q, %q, %q)", gotDepartmentID, gotCategoryID, gotPriority, departmentID, categoryID, priority)
	}
}

func assertEventTimestamp(t *testing.T, pool *pgxpool.Pool, aggregateID uuid.UUID, eventType, field string) {
	t.Helper()
	var present bool
	if err := pool.QueryRow(
		context.Background(),
		`SELECT payload ? $3 FROM dispatch_outbox_events WHERE aggregate_id=$1 AND event_type=$2`,
		aggregateID,
		eventType,
		field,
	).Scan(&present); err != nil {
		t.Fatalf("query outbox timestamp %q error = %v", field, err)
	}
	if !present {
		t.Errorf("outbox event %q has no %q", eventType, field)
	}
}
