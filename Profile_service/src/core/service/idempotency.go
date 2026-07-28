package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"profile/models"
	profilepkg "profile/pkg"
	"profile/src/core/repository"
)

const idempotencyTTL = 24 * time.Hour

func withIdempotency[T any](
	ctx context.Context,
	repo *repository.Repository,
	operation string,
	actorKey string,
	request any,
	fn func() (*T, uuid.UUID, error),
) (*T, error) {
	key, ok := profilepkg.IdempotencyKeyFromContext(ctx)
	if !ok {
		result, _, err := fn()
		return result, err
	}

	requestHash, err := hashRequest(request)
	if err != nil {
		return nil, err
	}

	record, acquired, err := repo.BeginIdempotency(ctx, actorKey, operation, key, requestHash, idempotencyTTL)
	if err != nil {
		return nil, err
	}

	if !acquired {
		if record.RequestHash != requestHash {
			return nil, models.ErrIdempotencyConflict
		}
		switch record.Status {
		case "COMPLETED":
			var result T
			if err = json.Unmarshal(record.Response, &result); err != nil {
				return nil, fmt.Errorf("service: idempotency: decode cached response: %w", err)
			}
			return &result, nil
		case "PROCESSING":
			return nil, models.ErrIdempotencyInProgress
		case "FAILED":
			return nil, models.ErrIdempotencyFailed
		default:
			return nil, fmt.Errorf("service: idempotency: unknown status %q", record.Status)
		}
	}

	result, resourceID, err := fn()
	if err != nil {
		_ = repo.FailIdempotency(ctx, actorKey, operation, key, err)
		return nil, err
	}

	response, err := json.Marshal(result)
	if err != nil {
		_ = repo.FailIdempotency(ctx, actorKey, operation, key, err)
		return nil, fmt.Errorf("service: idempotency: encode response: %w", err)
	}

	if err = repo.CompleteIdempotency(ctx, actorKey, operation, key, response, operation, resourceID); err != nil {
		return nil, err
	}

	return result, nil
}

func hashRequest(request any) (string, error) {
	bytes, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("service: idempotency: encode request: %w", err)
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}
