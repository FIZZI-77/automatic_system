package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

func insertOutboxEvent(
	ctx context.Context,
	exec DBTX,
	aggregateType string,
	aggregateID uuid.UUID,
	eventType string,
	payload any,
) error {
	payloadBytes, err := json.Marshal(payload)
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
			created_at
		)
		VALUES ($1, $2, $3, $4, $5::jsonb, 'PENDING', 0, now())
	`

	_, err = exec.Exec(
		ctx,
		query,
		uuid.New(),
		aggregateType,
		aggregateID,
		eventType,
		string(payloadBytes),
	)
	if err != nil {
		return fmt.Errorf("outbox: insert event: %w", err)
	}

	return nil
}
