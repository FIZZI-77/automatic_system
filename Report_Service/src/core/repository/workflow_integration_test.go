//go:build integration

package repository

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"report/models"
)

func TestReportClaimFencingAndOutbox(t *testing.T) {
	pool := peripheralPool(t)
	r := NewReportRepoStruct(pool)
	ctx := t.Context()
	v, err := r.Create(ctx, models.CreateInput{RequestedBy: uuid.New(), Name: "Report", Type: models.TypeTicketOverview, Format: models.FormatCSV, ActorRoles: []string{"admin"}})
	if err != nil {
		t.Fatalf("Create = %v", err)
	}
	first, err := r.Claim(ctx)
	if err != nil || first.ID != v.ID || first.Attempts != 1 {
		t.Fatalf("Claim(first) = %+v, %v", first, err)
	}
	if _, err := r.Claim(ctx); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("Claim(active job) = %v; want no rows", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE reports SET updated_at=now()-interval '6 minutes' WHERE id=$1`, v.ID); err != nil {
		t.Fatal(err)
	}
	second, err := r.Claim(ctx)
	if err != nil || second.Attempts != 2 {
		t.Fatalf("Claim(expired lease) = %+v, %v", second, err)
	}
	if err := r.Complete(ctx, v.ID, uuid.New(), first.Attempts); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("Complete(stale attempt) = %v; want no rows", err)
	}
	if err := r.Fail(ctx, v.ID, first.Attempts, "stale"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("Fail(stale attempt) = %v; want no rows", err)
	}
	file := uuid.New()
	if err := r.Complete(ctx, v.ID, file, second.Attempts); err != nil {
		t.Fatalf("Complete(current attempt) = %v", err)
	}
	got, err := r.Get(ctx, v.ID)
	if err != nil || got.Status != models.StatusCompleted || got.FileID == nil || *got.FileID != file {
		t.Fatalf("Get(completed) = %+v, %v", got, err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE aggregate_id=$1`, v.ID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("outbox count = %d, %v; want 2", count, err)
	}
	if _, err := r.Cancel(ctx, v.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("Cancel(completed) = %v", err)
	}
}
func TestReportCreateRollsBackOnOutboxFailure(t *testing.T) {
	pool := peripheralPool(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `ALTER TABLE outbox_events ADD CONSTRAINT reject_test_event CHECK (false) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	_, err := NewReportRepoStruct(pool).Create(ctx, models.CreateInput{RequestedBy: uuid.New(), Name: "Report", Type: models.TypeTicketOverview, Format: models.FormatCSV, ActorRoles: []string{}})
	if err == nil {
		t.Fatal("Create succeeded despite rejected outbox event")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM reports`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("reports after rollback = %d, %v; want 0", count, err)
	}
}
