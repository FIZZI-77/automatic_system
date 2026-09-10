package main

import (
	"context"
	"os"
	"sync"
	"time"

	"routing/pkg/closer"
	"routing/src/infrastructure/outboxrelay"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func startOutboxRelay(
	ctx context.Context,
	workers *sync.WaitGroup,
	db *pgxpool.Pool,
	dependencies *closer.Closer,
	logger *zap.Logger,
) {
	brokers := split(os.Getenv("KAFKA_BROKERS"))
	if len(brokers) == 0 {
		logger.Warn("outbox relay disabled: KAFKA_BROKERS is empty")
		return
	}
	worker, err := outboxrelay.New(
		db,
		outboxrelay.Config{
			Brokers:      brokers,
			Topic:        env("KAFKA_ROUTING_TOPIC", "routing.events.v1"),
			PollInterval: time.Second,
			BatchSize:    50,
			MaxAttempts:  10,
			WorkerCount:  envInt("OUTBOX_WORKER_COUNT", 4),
		},
		logger,
	)
	if err != nil {
		fatalWithCleanup(
			logger,
			dependencies,
			"create outbox relay",
			err,
		)
	}
	dependencies.Add("outbox relay", worker.Close)
	workers.Add(1)
	go func() {
		defer workers.Done()
		if runErr := worker.Run(ctx); runErr != nil {
			logger.Error("outbox relay stopped", zap.Error(runErr))
		}
	}()
}
