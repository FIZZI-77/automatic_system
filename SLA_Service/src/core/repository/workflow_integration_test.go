//go:build integration

package repository

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"sla/models"
)

func TestSLAEventAndDeadlineIdempotency(t *testing.T) {
	pool := peripheralPool(t)
	r := New(pool)
	ctx := t.Context()
	rule, err := r.CreateRule(ctx, &models.Rule{Name: "test rule", ResponseTime: time.Hour, ResolutionTime: 2 * time.Hour, WarningPercent: 80})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := models.TicketEvent{EventID: uuid.NewString(), EventType: "ticket.created", TicketID: uuid.New(), DepartmentID: uuid.New(), CategoryID: uuid.New(), Priority: models.PriorityHigh, CreatedAt: start, UpdatedAt: start}
	for range 2 {
		if err := r.ApplyEvent(ctx, e, rule); err != nil {
			t.Fatalf("ApplyEvent = %v", err)
		}
	}
	got, err := r.GetTicketSLA(ctx, e.TicketID)
	if err != nil || got.Version != 1 || !got.ResponseDeadline.Equal(start.Add(time.Hour)) {
		t.Fatalf("GetTicketSLA = %+v, %v", got, err)
	}
	for range 2 {
		if err := r.CheckDeadlines(ctx, start.Add(49*time.Minute)); err != nil {
			t.Fatalf("CheckDeadlines(warning) = %v", err)
		}
	}
	for range 2 {
		if err := r.CheckDeadlines(ctx, start.Add(3*time.Hour)); err != nil {
			t.Fatalf("CheckDeadlines(breach) = %v", err)
		}
	}
	got, err = r.GetTicketSLA(ctx, e.TicketID)
	if err != nil || !got.ResponseWarningSent || !got.ResponseBreached || !got.ResolutionBreached {
		t.Fatalf("GetTicketSLA(breached) = %+v, %v", got, err)
	}
	history, total, err := r.ListHistory(ctx, e.TicketID, 20, 0)
	if err != nil || total != 4 || len(history) != 4 {
		t.Fatalf("ListHistory = %d entries, total %d, %v; want 4", len(history), total, err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events`).Scan(&count); err != nil || count != 4 {
		t.Fatalf("SLA outbox = %d, %v; want 4", count, err)
	}
}

func TestSLALateDeadlineCheckDoesNotSendWarnings(t *testing.T) {
	pool := peripheralPool(t)
	r := New(pool)
	ctx := t.Context()
	rule, err := r.CreateRule(ctx, &models.Rule{Name: "late check", ResponseTime: time.Hour, ResolutionTime: 2 * time.Hour, WarningPercent: 80})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	event := models.TicketEvent{EventID: uuid.NewString(), EventType: "ticket.created", TicketID: uuid.New(), DepartmentID: uuid.New(), CategoryID: uuid.New(), Priority: models.PriorityHigh, CreatedAt: start}
	if err := r.ApplyEvent(ctx, event, rule); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := r.CheckDeadlines(ctx, start.Add(3*time.Hour)); err != nil {
			t.Fatalf("CheckDeadlines(late) = %v", err)
		}
	}
	got, err := r.GetTicketSLA(ctx, event.TicketID)
	if err != nil || !got.ResponseBreached || !got.ResolutionBreached || got.ResponseWarningSent || got.ResolutionWarningSent {
		t.Fatalf("GetTicketSLA(late check) = %+v, %v; want breaches without warnings", got, err)
	}
	_, total, err := r.ListHistory(ctx, event.TicketID, 20, 0)
	if err != nil || total != 3 {
		t.Fatalf("late check history = %d, %v; want CREATED and two breaches", total, err)
	}
}
