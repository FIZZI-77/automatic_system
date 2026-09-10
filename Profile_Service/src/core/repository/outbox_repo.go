package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	profilepkg "profile/pkg"
)

type outboxEnvelope struct {
	EventID      uuid.UUID  `json:"event_id"`
	EventType    string     `json:"event_type"`
	EventVersion int        `json:"event_version"`
	AggregateID  uuid.UUID  `json:"aggregate_id"`
	OccurredAt   time.Time  `json:"occurred_at"`
	RequestID    *string    `json:"request_id,omitempty"`
	ActorUserID  *uuid.UUID `json:"actor_user_id,omitempty"`
	Payload      any        `json:"payload"`
}

func insertOutboxEvent(
	ctx context.Context,
	q Querier,
	aggregateType string,
	aggregateID uuid.UUID,
	eventType string,
	actorUserID *uuid.UUID,
	payload any,
) error {
	eventID := uuid.New()
	now := time.Now().UTC()

	var requestID *string
	if value, ok := profilepkg.RequestIDFromContext(ctx); ok {
		requestID = &value
	}

	envelope := outboxEnvelope{
		EventID:      eventID,
		EventType:    eventType,
		EventVersion: 1,
		AggregateID:  aggregateID,
		OccurredAt:   now,
		RequestID:    requestID,
		ActorUserID:  actorUserID,
		Payload:      payload,
	}

	payloadBytes, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("outbox: marshal payload: %w", err)
	}

	const query = `
		INSERT INTO outbox_events (
			id,
			aggregate_type,
			aggregate_id,
			event_type,
			payload,
			status,
			attempts,
			next_attempt_at,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5::jsonb, 'PENDING', 0, $6, $6)
	`

	if _, err = q.Exec(ctx, query, eventID, aggregateType, aggregateID, eventType, string(payloadBytes), now); err != nil {
		return fmt.Errorf("outbox: insert event: %w", err)
	}

	return nil
}
