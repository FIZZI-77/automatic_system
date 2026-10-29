package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"auth/models"
	"auth/pkg"

	"github.com/google/uuid"
)

const idempotencyTTL = 24 * time.Hour

// withIdempotency выполняет fn и сохраняет её результат в общей транзакции по ключу из ctx.
// Запись действует 24 часа; повтор с другим запросом вызывает ErrIdempotencyConflict.
// Без ключа вызывает fn напрямую, без сохранения ответа.
func (a *AuthServiceStruct) withIdempotency(
	ctx context.Context,
	operation string,
	actorKey string,
	request any,
	fn func(context.Context) (any, uuid.UUID, error),
) (any, error) {
	key, ok := pkg.IdempotencyKeyFromContext(ctx)

	if !ok {
		result, _, err := fn(ctx)
		return result, err
	}

	requestHash, err := hashRequest(request)

	if err != nil {
		return nil, err
	}

	result, record, acquired, err := a.repo.RunIdempotentTx(ctx, actorKey, operation, key, requestHash, idempotencyTTL, func(txCtx context.Context) (any, any, error) {
		value, resourceID, runErr := fn(txCtx)
		return value, resourceID, runErr
	})

	if err != nil {
		return nil, err
	}

	if !acquired {

		if record.RequestHash != requestHash {
			return nil, models.ErrIdempotencyConflict
		}

		switch record.Status {
		case "COMPLETED":
			var result any

			if err = json.Unmarshal(record.Response, &result); err != nil {
				return nil, fmt.Errorf("service: idempotency: decode cached response: %w", err)
			}

			return result, nil
		case "PROCESSING":
			return nil, models.ErrIdempotencyInProgress
		case "FAILED":
			return nil, models.ErrIdempotencyFailed
		default:
			return nil, fmt.Errorf("service: idempotency: unknown status %q", record.Status)
		}
	}

	return result, nil
}

// withExternalSideEffectIdempotency защищает fn от повторов, выполняя SMTP вне транзакции БД.
// Занимает ключ на 24 часа и отдельно сохраняет результат либо состояние FAILED.
// Используется до переноса отправки писем в постоянный почтовый outbox.
func (a *AuthServiceStruct) withExternalSideEffectIdempotency(
	ctx context.Context,
	operation string,
	actorKey string,
	request any,
	fn func(context.Context) (any, uuid.UUID, error),
) (any, error) {
	key, ok := pkg.IdempotencyKeyFromContext(ctx)

	if !ok {
		result, _, err := fn(ctx)
		return result, err
	}

	requestHash, err := hashRequest(request)

	if err != nil {
		return nil, err
	}

	record, acquired, err := a.repo.BeginIdempotency(ctx, actorKey, operation, key, requestHash, idempotencyTTL)

	if err != nil {
		return nil, err
	}

	if !acquired {

		if record.RequestHash != requestHash {
			return nil, models.ErrIdempotencyConflict
		}

		switch record.Status {
		case "COMPLETED":
			var result any

			if err = json.Unmarshal(record.Response, &result); err != nil {
				return nil, fmt.Errorf("service: idempotency: decode cached response: %w", err)
			}

			return result, nil
		case "PROCESSING":
			return nil, models.ErrIdempotencyInProgress
		case "FAILED":
			return nil, models.ErrIdempotencyFailed
		default:
			return nil, fmt.Errorf("service: idempotency: unknown status %q", record.Status)
		}
	}

	result, resourceID, err := fn(ctx)

	if err != nil {
		_ = a.repo.FailIdempotency(ctx, actorKey, operation, key, err)
		return nil, err
	}

	response, err := json.Marshal(result)

	if err != nil {
		_ = a.repo.FailIdempotency(ctx, actorKey, operation, key, err)
		return nil, fmt.Errorf("service: idempotency: encode response: %w", err)
	}

	if err = a.repo.CompleteIdempotency(ctx, actorKey, operation, key, response, operation, resourceID); err != nil {
		return nil, err
	}

	return result, nil
}

// cachedResult возвращает результат как *T либо восстанавливает этот тип через JSON.
// Ошибки сериализации и разбора передаёт вызывающему без подмены результата.
func cachedResult[T any](result any) (*T, error) {

	if typed, ok := result.(*T); ok {
		return typed, nil
	}

	bytes, err := json.Marshal(result)

	if err != nil {
		return nil, err
	}

	var typed T

	if err = json.Unmarshal(bytes, &typed); err != nil {
		return nil, err
	}

	return &typed, nil
}

// hashRequest вычисляет шестнадцатеричный SHA-256 JSON-представления запроса.
// Возвращает ошибку, если значение не удаётся сериализовать.
func hashRequest(request any) (string, error) {
	bytes, err := json.Marshal(request)

	if err != nil {
		return "", fmt.Errorf("service: idempotency: encode request: %w", err)
	}

	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}
