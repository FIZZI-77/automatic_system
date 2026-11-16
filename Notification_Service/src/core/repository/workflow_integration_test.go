//go:build integration

package repository

import (
	"testing"

	"github.com/google/uuid"

	"notification/models"
)

func TestDispatchIdempotencyAndOwnership(t *testing.T) {
	pool := peripheralPool(t)
	r := New(pool)
	ctx := t.Context()
	user := uuid.New()
	e := models.Event{ID: uuid.NewString(), Type: "ticket.created", Topic: "tickets.events.v1", Payload: map[string]any{"ticket_id": uuid.NewString(), "user_id": user.String()}}
	first, err := r.Dispatch(ctx, e, []uuid.UUID{user})
	if err != nil || len(first) != 1 {
		t.Fatalf("Dispatch(first) = %v, %v", first, err)
	}
	second, err := r.Dispatch(ctx, e, []uuid.UUID{user})
	if err != nil || len(second) != 0 {
		t.Fatalf("Dispatch(replay) = %v, %v; want no new notifications", second, err)
	}
	var notifications, deliveries int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM notifications`).Scan(&notifications); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM deliveries`).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if notifications != 1 || deliveries != 1 {
		t.Fatalf("dispatch counts = %d notifications, %d deliveries; want 1 each", notifications, deliveries)
	}
	if _, err := r.MarkRead(ctx, uuid.New(), first[0].ID); err == nil {
		t.Fatal("MarkRead accepted another user")
	}
	got, err := r.MarkRead(ctx, user, first[0].ID)
	if err != nil || !got.Read || got.ReadAt == nil {
		t.Fatalf("MarkRead(owner) = %+v, %v", got, err)
	}
	again, err := r.MarkRead(ctx, user, first[0].ID)
	if err != nil || !again.ReadAt.Equal(*got.ReadAt) {
		t.Fatalf("MarkRead(replay) = %+v, %v; want stable read timestamp", again, err)
	}
}
func TestDispatchRollsBackInboxOnDeliveryFailure(t *testing.T) {
	pool := peripheralPool(t)
	r := New(pool)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `ALTER TABLE deliveries ADD CONSTRAINT reject_test_delivery CHECK (false) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	e := models.Event{ID: uuid.NewString(), Type: "ticket.created", Payload: map[string]any{}}
	if _, err := r.Dispatch(ctx, e, []uuid.UUID{uuid.New()}); err == nil {
		t.Fatal("Dispatch succeeded despite rejected delivery")
	}
	for _, table := range []string{"event_inbox", "notifications", "deliveries"} {
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s after rollback = %d, %v; want 0", table, count, err)
		}
	}
}
