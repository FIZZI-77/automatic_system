//go:build integration

package outboxrelay

import (
	"testing"

	"github.com/google/uuid"
	"notification/models"
	"notification/src/core/repository"
)

func TestNotificationEventsDeduplicateAndRollback(t *testing.T) {
	db := outboxPool(t)
	repo := repository.New(db)
	user := uuid.New()
	event := models.Event{ID: uuid.NewString(), Type: "ticket.created", Topic: "tickets.events.v1", Payload: map[string]any{"user_id": user.String()}}
	items, err := repo.Dispatch(t.Context(), event, []uuid.UUID{user})
	if err != nil || len(items) != 1 {
		t.Fatalf("Dispatch = %v, %v, want one notification", items, err)
	}
	if _, err := repo.Dispatch(t.Context(), event, []uuid.UUID{user}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.MarkRead(t.Context(), user, items[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.MarkRead(t.Context(), user, items[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.MarkAllRead(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	delivery, _, err := repo.ClaimDelivery(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.DeliveryFailed(t.Context(), delivery, "private provider error"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `UPDATE deliveries SET next_attempt_at=now()`); err != nil {
		t.Fatal(err)
	}
	delivery, _, err = repo.ClaimDelivery(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.DeliverySent(t.Context(), delivery.ID, delivery.Attempts, "private provider id"); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeliverySent(t.Context(), delivery.ID, delivery.Attempts, "private provider id"); err == nil {
		t.Fatal("stale DeliverySent succeeded, want error")
	}
	var count int
	var sensitive bool
	if err := db.QueryRow(t.Context(), `SELECT count(*),bool_or(payload ?| ARRAY['title','body','recipient','token','provider_id','last_error']) FROM outbox_events`).Scan(&count, &sensitive); err != nil || count != 4 || sensitive {
		t.Fatalf("notification events = (count %d, sensitive %v, %v), want created, read, failed, sent without delivery secrets", count, sensitive, err)
	}
	_, err = db.Exec(t.Context(), `CREATE FUNCTION reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'outbox unavailable'; END $$;
        CREATE TRIGGER reject_event BEFORE INSERT ON outbox_events FOR EACH ROW EXECUTE FUNCTION reject_event()`)
	if err != nil {
		t.Fatal(err)
	}
	event.ID = uuid.NewString()
	if _, err := repo.Dispatch(t.Context(), event, []uuid.UUID{user}); err == nil {
		t.Fatal("Dispatch(outbox failure) succeeded, want rollback")
	}
	if err := db.QueryRow(t.Context(), `SELECT count(*) FROM event_inbox WHERE event_id=$1`, event.ID).Scan(&count); err != nil || count != 0 {
		t.Errorf("inbox after outbox failure = %d, %v, want rolled back", count, err)
	}
}
