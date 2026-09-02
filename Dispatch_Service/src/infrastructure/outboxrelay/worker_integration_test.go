//go:build integration

package outboxrelay

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOutboxLeaseFencesPreviousReplica(t *testing.T) {
	databaseURL := os.Getenv("DISPATCH_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DISPATCH_TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	t.Cleanup(pool.Close)
	eventID := uuid.New()
	aggregateID := uuid.New()
	payload, err := json.Marshal(map[string]any{"event_id": eventID, "event_type": "dispatch.requested"})
	if err != nil {
		t.Fatalf("json.Marshal(outbox payload) error = %v", err)
	}
	if _, err = pool.Exec(t.Context(), `INSERT INTO dispatch_outbox_events(id,aggregate_id,event_type,payload) VALUES($1,$2,'dispatch.requested',$3)`, eventID, aggregateID, payload); err != nil {
		t.Fatalf("insert outbox fixture error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(t.Context(), "DELETE FROM dispatch_outbox_events WHERE id=$1", eventID)
	})

	firstOwner := uuid.New()
	first := &Worker{db: pool, cfg: Config{InstanceID: firstOwner}}
	if _, err = pool.Exec(t.Context(), `UPDATE dispatch_outbox_events SET status='PROCESSING',locked_at=now(),locked_by=$2 WHERE id=$1`, eventID, firstOwner); err != nil {
		t.Fatalf("claim outbox lease fixture error = %v", err)
	}
	claimed := event{ID: eventID, AggregateID: aggregateID, EventType: "dispatch.requested", Payload: payload, LockOwner: firstOwner}
	secondOwner := uuid.New()
	if _, err = pool.Exec(t.Context(), `UPDATE dispatch_outbox_events SET locked_by=$2 WHERE id=$1`, eventID, secondOwner); err != nil {
		t.Fatalf("transfer outbox lease fixture error = %v", err)
	}
	if err = first.markSent(t.Context(), claimed); !errors.Is(err, errLeaseLost) {
		t.Errorf("Worker.markSent(stale replica) error = %v, want %v", err, errLeaseLost)
	}
}
