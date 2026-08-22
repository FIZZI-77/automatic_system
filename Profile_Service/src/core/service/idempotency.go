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
	fn func(context.Context) (*T, uuid.UUID, error),
) (*T, error) {
	key, ok := profilepkg.IdempotencyKeyFromContext(ctx)
	if !ok {
		result, _, err := fn(ctx)
		return result, err
	}

	requestHash, err := hashRequest(request)
	if err != nil {
		return nil, err
	}

	rawResult, record, acquired, err := repo.RunIdempotentTx(ctx, actorKey, operation, key, requestHash, idempotencyTTL, func(txCtx context.Context) (any, any, error) {
		result, resourceID, runErr := fn(txCtx)
		return result, resourceID, runErr
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

	result, ok := rawResult.(*T)
	if !ok {
		return nil, fmt.Errorf("service: idempotency: unexpected result type %T", rawResult)
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
