package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"ticket/models"
	"ticket/pkg"
	"time"

	"github.com/google/uuid"
)

const idempotencyTTL = 24 * time.Hour

func (s *TicketServiceStruct) withIdempotency(ctx context.Context, operation string, actorKey string, request any, fn func() (any, uuid.UUID, error)) (any, error) {
	key, ok := pkg.IdempotencyKeyFromContext(ctx)
	if !ok {
		result, _, err := fn()
		return result, err
	}

	requestHash, err := hashRequest(request)
	if err != nil {
		return nil, err
	}

	record, acquired, err := s.repo.BeginIdempotency(ctx, actorKey, operation, key, requestHash, idempotencyTTL)
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

	result, resourceID, err := fn()
	if err != nil {
		_ = s.repo.FailIdempotency(ctx, actorKey, operation, key, err)
		return nil, err
	}

	response, err := json.Marshal(result)
	if err != nil {
		_ = s.repo.FailIdempotency(ctx, actorKey, operation, key, err)
		return nil, fmt.Errorf("service: idempotency: encode response: %w", err)
	}

	if err = s.repo.CompleteIdempotency(ctx, actorKey, operation, key, response, operation, resourceID); err != nil {
		return nil, err
	}

	return result, nil
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
