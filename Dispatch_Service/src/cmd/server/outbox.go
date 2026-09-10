package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"dispatch/src/infrastructure/outboxrelay"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func startOutboxRelay(
	ctx context.Context,
	db *pgxpool.Pool,
	workers *sync.WaitGroup,
	logger *zap.Logger,
) *outboxrelay.Worker {
	brokers := split(os.Getenv("KAFKA_BROKERS"))
	if len(brokers) == 0 {
		logger.Warn("dispatch outbox relay disabled: KAFKA_BROKERS is empty")
		return nil
	}
	worker, err := outboxrelay.New(db, outboxrelay.Config{
		Brokers:      brokers,
		Topic:        env("KAFKA_DISPATCH_TOPIC", "dispatch.events.v1"),
		BatchSize:    integer("OUTBOX_BATCH_SIZE", 50),
		PollInterval: time.Second,
		MaxAttempts:  10,
		WorkerCount:  integer("OUTBOX_WORKER_COUNT", 4),
	}, logger)
	if err != nil {
		logger.Fatal("create dispatch outbox relay", zap.Error(err))
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		if runErr := worker.Run(ctx); runErr != nil {
			logger.Error("dispatch outbox relay stopped", zap.Error(runErr))
		}
	}()
	return worker
}

func split(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}
