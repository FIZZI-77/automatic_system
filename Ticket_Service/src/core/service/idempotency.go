package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"ticket/models"
	"ticket/pkg"
	"ticket/src/core/repository"
	"time"

	"github.com/google/uuid"
)

const idempotencyTTL = 24 * time.Hour

func withIdempotency(repo *repository.Repository, ctx context.Context, operation string, actorKey string, request any, fn func(context.Context) (any, uuid.UUID, error)) (any, error) {
	key, ok := pkg.IdempotencyKeyFromContext(ctx)
	if !ok {
		result, _, err := fn(ctx)
		return result, err
	}

	requestHash, err := hashRequest(request)
	if err != nil {
		return nil, err
	}

	result, record, acquired, err := repo.RunIdempotentTx(ctx, actorKey, operation, key, requestHash, idempotencyTTL, func(txCtx context.Context) (any, any, error) {
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

func (s *TicketServiceStruct) withIdempotency(ctx context.Context, operation string, actorKey string, request any, fn func(context.Context) (any, uuid.UUID, error)) (any, error) {
	return withIdempotency(s.repo, ctx, operation, actorKey, request, fn)
}

func (s *CategoryServiceStruct) withIdempotency(ctx context.Context, operation string, actorKey string, request any, fn func(context.Context) (any, uuid.UUID, error)) (any, error) {
	return withIdempotency(s.repo, ctx, operation, actorKey, request, fn)
}

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

func hashRequest(request any) (string, error) {
	bytes, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("service: idempotency: encode request: %w", err)
	}

	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}

func idempotencyActor(actor *uuid.UUID, fallback uuid.UUID) string {
	if actor != nil {
		return actor.String()
	}
	if fallback != uuid.Nil {
		return fallback.String()
	}
	return ""
}
