package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type IdempotencyRecord struct {
	Status      string
	RequestHash string
	Response    []byte
	Error       sql.NullString
}

// beginIdempotency пытается вставить ключ операции через q и возвращает признак его захвата.
// Существующую запись читает с FOR UPDATE; сравнение хеша и статуса оставляет вызывающему.
func beginIdempotency(
	ctx context.Context,
	q DBTX,
	actorKey string,
	operation string,
	key string,
	requestHash string,
	ttl time.Duration,
) (*IdempotencyRecord, bool, error) {
	record := &IdempotencyRecord{}
	err := q.QueryRow(ctx, `
		INSERT INTO idempotency_keys (actor_key, operation, idempotency_key, request_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (actor_key, operation, idempotency_key) DO NOTHING
		RETURNING status, request_hash, response, error`,
		actorKey, operation, key, requestHash, time.Now().UTC().Add(ttl),
	).Scan(&record.Status, &record.RequestHash, &record.Response, &record.Error)

	if err == nil {
		return record, true, nil
	}

	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("repository: beginIdempotency(): insert: %w", err)
	}

	err = q.QueryRow(ctx, `
		SELECT status, request_hash, response, error FROM idempotency_keys
		WHERE actor_key = $1 AND operation = $2 AND idempotency_key = $3 FOR UPDATE`,
		actorKey, operation, key,
	).Scan(&record.Status, &record.RequestHash, &record.Response, &record.Error)

	if err != nil {
		return nil, false, fmt.Errorf("repository: beginIdempotency(): select: %w", err)
	}

	return record, false, nil
}

// completeIdempotency сохраняет ответ и ресурс, устанавливая COMPLETED и очищая ошибку.
// Возвращает ошибку, если изменена не ровно одна запись ключа.
func completeIdempotency(
	ctx context.Context,
	q DBTX,
	actorKey string,
	operation string,
	key string,
	response []byte,
	resourceID any,
) error {
	result, err := q.Exec(ctx, `
		UPDATE idempotency_keys SET status = 'COMPLETED', response = $4, error = NULL,
			resource_type = $5, resource_id = $6, updated_at = now()
		WHERE actor_key = $1 AND operation = $2 AND idempotency_key = $3`,
		actorKey, operation, key, response, operation, resourceID)

	if err != nil {
		return fmt.Errorf("repository: completeIdempotency(): update: %w", err)
	}

	if result.RowsAffected() != 1 {
		return fmt.Errorf("repository: completeIdempotency(): idempotency record not found")
	}

	return nil
}

// RunIdempotentTx выполняет захват ключа, fn и сохранение JSON-ответа в одной транзакции.
// Передаёт fn контекст общей транзакции; при занятом ключе возвращает существующую
// запись и acquired=false без вызова fn. Ошибки нового выполнения приводят к откату.
func (r *Repo) RunIdempotentTx(
	ctx context.Context,
	actorKey string,
	operation string,
	key string,
	requestHash string,
	ttl time.Duration,
	fn func(context.Context) (any, any, error),
) (any, *IdempotencyRecord, bool, error) {
	tx, err := r.writePool.Begin(ctx)

	if err != nil {
		return nil, nil, false, fmt.Errorf("repository: RunIdempotentTx(): begin: %w", err)
	}

	defer rollbackTxOnCancel(ctx, tx)()
	record, acquired, err := beginIdempotency(ctx, tx, actorKey, operation, key, requestHash, ttl)

	if err != nil || !acquired {
		return nil, record, acquired, err
	}

	result, resourceID, err := fn(contextWithCommandTx(ctx, tx))

	if err != nil {
		return nil, nil, true, err
	}

	response, err := json.Marshal(result)

	if err != nil {
		return nil, nil, true, fmt.Errorf("repository: RunIdempotentTx(): encode response: %w", err)
	}

	if err = completeIdempotency(ctx, tx, actorKey, operation, key, response, resourceID); err != nil {
		return nil, nil, true, err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, nil, true, fmt.Errorf("repository: RunIdempotentTx(): commit: %w", err)
	}

	return result, record, true, nil
}

// BeginIdempotency отдельно занимает ключ операции со сроком ttl либо читает существующий.
// Возвращает запись и признак успешной вставки; внешнюю операцию и ответ не сохраняет.
func (r *Repo) BeginIdempotency(
	ctx context.Context,
	actorKey string,
	operation string,
	key string,
	requestHash string,
	ttl time.Duration,
) (*IdempotencyRecord, bool, error) {

	if r.writePool == nil {
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
	err := r.writePool.QueryRow(ctx, query, actorKey, operation, key, requestHash, expiresAt).
		Scan(&record.Status, &record.RequestHash, &record.Response, &record.Error)

	if err == nil {
		return record, true, nil
	}

	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("repository: BeginIdempotency(): insert: %w", err)
	}

	selectQuery := `
		SELECT status, request_hash, response, error
		FROM idempotency_keys
		WHERE actor_key = $1
		  AND operation = $2
		  AND idempotency_key = $3
	`
	err = r.writePool.QueryRow(ctx, selectQuery, actorKey, operation, key).
		Scan(&record.Status, &record.RequestHash, &record.Response, &record.Error)

	if err != nil {
		return nil, false, fmt.Errorf("repository: BeginIdempotency(): select: %w", err)
	}

	return record, false, nil
}

// CompleteIdempotency сохраняет ответ и ресурс завершённой операции, очищая прежнюю ошибку.
// Использует корневой пул записи; отсутствие строки по ключу отдельно не проверяет.
func (r *Repo) CompleteIdempotency(ctx context.Context, actorKey, operation, key string, response []byte, resourceType string, resourceID any) error {

	if r.writePool == nil {
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
	_, err := r.writePool.Exec(ctx, query, actorKey, operation, key, response, resourceType, resourceID)

	if err != nil {
		return fmt.Errorf("repository: CompleteIdempotency(): update: %w", err)
	}

	return nil
}

// FailIdempotency помечает операцию FAILED и сохраняет текст operationErr либо пустую строку.
// Отсутствие записи по ключу отдельно не проверяет.
func (r *Repo) FailIdempotency(ctx context.Context, actorKey, operation, key string, operationErr error) error {

	if r.writePool == nil {
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
	_, err := r.writePool.Exec(ctx, query, actorKey, operation, key, errText)

	if err != nil {
		return fmt.Errorf("repository: FailIdempotency(): update: %w", err)
	}

	return nil
}
