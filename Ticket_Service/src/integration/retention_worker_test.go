package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"ticket/src/infrastructure/retentionworker"
)

func TestRetentionWorkerArchivesTerminalTicket(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()
	category := createIntegrationCategory(t, app)
	ticket := createIntegrationTicket(t, app, category.ID, uuid.New())
	completedAt := time.Now().UTC().Add(-25 * time.Hour)

	if _, err := app.db.Exec(ctx, `
		UPDATE tickets
		SET status='DONE', completed_at=$3, updated_at=$3
		WHERE department_id=$1 AND id=$2`, ticket.DepartmentID, ticket.ID, completedAt); err != nil {
		t.Fatalf("prepare terminal ticket: %v", err)
	}

	worker, err := retentionworker.New(app.db, retentionworker.Config{
		ArchiveAfter: 24 * time.Hour,
		PurgeAfter:   30 * 24 * time.Hour,
		BatchSize:    10,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("create retention worker: %v", err)
	}

	archived, err := worker.ArchiveOnce(ctx)
	if err != nil {
		t.Fatalf("archive terminal ticket: %v", err)
	}
	if archived != 1 {
		t.Fatalf("archived count = %d, want 1", archived)
	}

	var status string
	var archivedAt time.Time
	if err = app.db.QueryRow(ctx, `
		SELECT status, archived_at
		FROM tickets
		WHERE department_id=$1 AND id=$2`, ticket.DepartmentID, ticket.ID).Scan(&status, &archivedAt); err != nil {
		t.Fatalf("read archived ticket: %v", err)
	}
	if status != "ARCHIVED" {
		t.Fatalf("ticket status = %q, want ARCHIVED", status)
	}
	if archivedAt.IsZero() {
		t.Fatal("archived_at was not set")
	}

	var historyCount int
	if err = app.db.QueryRow(ctx, `
		SELECT count(*)
		FROM ticket_status_history
		WHERE department_id=$1 AND ticket_id=$2 AND old_status='DONE' AND new_status='ARCHIVED'`,
		ticket.DepartmentID, ticket.ID,
	).Scan(&historyCount); err != nil {
		t.Fatalf("read archive history: %v", err)
	}
	if historyCount != 1 {
		t.Fatalf("archive history count = %d, want 1", historyCount)
	}

	var eventCount int
	if err = app.db.QueryRow(ctx, `
		SELECT count(*)
		FROM outbox_events
		WHERE aggregate_id=$1 AND event_type='ticket.archived'`, ticket.ID).Scan(&eventCount); err != nil {
		t.Fatalf("read archive event: %v", err)
	}
	if eventCount != 1 {
		t.Fatalf("archive event count = %d, want 1", eventCount)
	}
}
