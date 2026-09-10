package main

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"ticket/pkg/closer"
	"ticket/src/infrastructure/completionsaga"
)

func startCompletionSaga(db *pgxpool.Pool, dependencies *closer.Closer, logger *zap.Logger) {
	worker, err := completionsaga.New(db, completionsaga.Config{
		AttemptTimeout: envDuration("COMPLETION_SAGA_ATTEMPT_TIMEOUT", 10*time.Minute),
		PollInterval:   envDuration("COMPLETION_SAGA_POLL_INTERVAL", 30*time.Second),
		MaxAttempts:    envInt("COMPLETION_SAGA_MAX_ATTEMPTS", 3),
		BatchSize:      envInt("COMPLETION_SAGA_BATCH_SIZE", 50),
	}, logger)
	if err != nil {
		logger.Fatal("failed to initialize completion saga", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	dependencies.Add("completion saga", func() error {
		cancel()
		return nil
	})
	go func() {
		if err := worker.Run(ctx); err != nil {
			logger.Error("completion saga stopped", zap.Error(err))
		}
	}()
}
