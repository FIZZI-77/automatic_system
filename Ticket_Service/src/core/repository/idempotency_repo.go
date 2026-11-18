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

// beginIdempotency вставляет ключ операции со сроком ttl либо читает существующий с FOR UPDATE.
// Возвращает запись и признак новой вставки; соответствие хеша и статуса проверяет вызывающий.
func beginIdempotency(ctx context.Context, q Querier, actorKey, operation, key, requestHash string, ttl time.Duration) (*IdempotencyRecord, bool, error) {
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

// completeIdempotency помечает ключ COMPLETED, сохраняет ответ и ресурс и очищает ошибку.
// Требует изменения ровно одной записи; использует текущий исполнитель транзакции q.
func completeIdempotency(ctx context.Context, q Querier, actorKey, operation, key string, response []byte, resourceID any) error {
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
// Передаёт fn контекст общей транзакции. Для существующего ключа возвращает его запись
// и acquired=false без вызова fn; ошибочное новое выполнение откатывает.
func (r *Repository) RunIdempotentTx(ctx context.Context, actorKey, operation, key, requestHash string, ttl time.Duration, fn func(context.Context) (any, any, error)) (any, *IdempotencyRecord, bool, error) {
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

// BeginIdempotency отдельно занимает ключ либо возвращает существующую запись без блокировки.
// Булев результат показывает новую вставку; для работы требуется корневой пул записи.
func (r *Repository) BeginIdempotency(ctx context.Context, actorKey, operation, key, requestHash string, ttl time.Duration) (*IdempotencyRecord, bool, error) {

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

// CompleteIdempotency устанавливает COMPLETED и сохраняет готовый ответ и ссылку на ресурс.
// Использует корневой пул; отсутствие записи по ключу отдельно не проверяет.
func (r *Repository) CompleteIdempotency(ctx context.Context, actorKey, operation, key string, response []byte, resourceType string, resourceID any) error {

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

// FailIdempotency устанавливает FAILED и сохраняет текст ошибки либо пустую строку при nil.
// Отсутствие записи по ключу отдельно не проверяет.
func (r *Repository) FailIdempotency(ctx context.Context, actorKey, operation, key string, operationErr error) error {

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
