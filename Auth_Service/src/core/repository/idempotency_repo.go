package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type IdempotencyRecord struct {
	Status      string
	RequestHash string
	Response    []byte
	Error       sql.NullString
}

func (r *Repo) BeginIdempotency(ctx context.Context, actorKey, operation, key, requestHash string, ttl time.Duration) (*IdempotencyRecord, bool, error) {
	if r.db == nil {
		return nil, false, fmt.Errorf("repository: BeginIdempotency(): root db is unavailable")
	}

	expiresAt := time.Now().UTC().Add(ttl)
	query := `
		INSERT INTO idempotency_keys (
			actor_key,
			operation,
			idempotency_key,
			request_hash,
			expires_at
		)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (actor_key, operation, idempotency_key) DO NOTHING
		RETURNING status, request_hash, response, error
	`

	record := &IdempotencyRecord{}
	err := r.db.QueryRowContext(ctx, query, actorKey, operation, key, requestHash, expiresAt).
		Scan(&record.Status, &record.RequestHash, &record.Response, &record.Error)
	if err == nil {
		return record, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, fmt.Errorf("repository: BeginIdempotency(): insert: %w", err)
	}

	selectQuery := `
		SELECT status, request_hash, response, error
		FROM idempotency_keys
		WHERE actor_key = $1
		  AND operation = $2
		  AND idempotency_key = $3
	`
	err = r.db.QueryRowContext(ctx, selectQuery, actorKey, operation, key).
		Scan(&record.Status, &record.RequestHash, &record.Response, &record.Error)
	if err != nil {
		return nil, false, fmt.Errorf("repository: BeginIdempotency(): select: %w", err)
	}

	return record, false, nil
}

func (r *Repo) CompleteIdempotency(ctx context.Context, actorKey, operation, key string, response []byte, resourceType string, resourceID any) error {
	if r.db == nil {
		return fmt.Errorf("repository: CompleteIdempotency(): root db is unavailable")
	}

	query := `
		UPDATE idempotency_keys
		SET status = 'COMPLETED',
			response = $4,
			error = NULL,
			resource_type = $5,
			resource_id = $6,
			updated_at = now()
		WHERE actor_key = $1
		  AND operation = $2
		  AND idempotency_key = $3
	`
	_, err := r.db.ExecContext(ctx, query, actorKey, operation, key, response, resourceType, resourceID)
	if err != nil {
		return fmt.Errorf("repository: CompleteIdempotency(): update: %w", err)
	}

	return nil
}

func (r *Repo) FailIdempotency(ctx context.Context, actorKey, operation, key string, operationErr error) error {
	if r.db == nil {
		return fmt.Errorf("repository: FailIdempotency(): root db is unavailable")
	}

	errText := ""
	if operationErr != nil {
		errText = operationErr.Error()
	}

	query := `
		UPDATE idempotency_keys
		SET status = 'FAILED',
			error = $4,
			updated_at = now()
		WHERE actor_key = $1
		  AND operation = $2
		  AND idempotency_key = $3
	`
	_, err := r.db.ExecContext(ctx, query, actorKey, operation, key, errText)
	if err != nil {
		return fmt.Errorf("repository: FailIdempotency(): update: %w", err)
	}

	return nil
}
