package repository

import (
	"testing"
	"time"

	"analytics/models"
)

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

func TestEventTimeUsesExplicitOccurredAt(t *testing.T) {
	envelope := time.Date(2026, 8, 17, 9, 30, 0, 0, time.UTC)
	want := time.Date(2026, 8, 17, 9, 15, 0, 0, time.UTC)
	got := eventTime(models.Event{
		Timestamp: envelope,
		Payload: map[string]any{"occurred_at": want.Format(time.RFC3339Nano)},
	})
	if !got.Equal(want) {
		t.Fatalf("eventTime() = %v, want explicit occurrence time %v", got, want)
	}
}
