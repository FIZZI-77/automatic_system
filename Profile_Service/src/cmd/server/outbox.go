package main

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"profile/pkg/closer"
	"profile/src/infrastructure/outboxrelay"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func startOutboxRelay(db *pgxpool.Pool, dependencies *closer.Closer, logger *zap.Logger) {
	raw := os.Getenv("KAFKA_BROKERS")
	if strings.TrimSpace(raw) == "" {
		logger.Warn("outbox relay disabled: KAFKA_BROKERS is empty")
		return
	}
	worker, err := outboxrelay.New(db, outboxrelay.Config{
		Brokers: strings.Split(raw, ","), Topic: "profiles.events.v1",
		PollInterval: time.Second, BatchSize: 50, MaxAttempts: 10,
		WorkerCount: outboxWorkerCount(),
	}, logger)
	if err != nil {
		logger.Fatal("failed to initialize outbox relay", zap.Error(err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	dependencies.Add("outbox relay", func() error { cancel(); return worker.Close() })
	go func() {
		if err := worker.Run(ctx); err != nil {
			logger.Error("outbox relay stopped", zap.Error(err))
		}
	}()
}

func outboxWorkerCount() int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv("OUTBOX_WORKER_COUNT")))
	if err != nil || value <= 0 {
		return 4
	}
	return value
}
