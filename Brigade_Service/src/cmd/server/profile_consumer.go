package main

import (
	"context"
	"os"
	"strconv"
	"strings"

	"brigade/pkg/closer"
	"brigade/src/infrastructure/profileconsumer"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func startProfileConsumer(db *pgxpool.Pool, dependencies *closer.Closer, logger *zap.Logger) {
	raw := strings.TrimSpace(os.Getenv("KAFKA_BROKERS"))
	if raw == "" {
		logger.Warn("profile inbox consumer disabled: KAFKA_BROKERS is empty")
		return
	}
	worker, err := profileconsumer.New(db, profileconsumer.Config{
		Brokers:      strings.Split(raw, ","),
		Topic:        "profiles.events.v1",
		GroupID:      envOrDefault("PROFILE_KAFKA_GROUP_ID", "brigade-profile-projection-v1"),
		Workers:      envPositiveInt("PROFILE_CONSUMER_WORKER_COUNT", 4),
		RetryWorkers: envPositiveInt("PROFILE_RETRY_WORKER_COUNT", 2),
	}, logger)
	if err != nil {
		logger.Fatal("failed to initialize profile inbox consumer", zap.Error(err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	dependencies.Add("profile inbox consumer", func() error {
		cancel()
		return worker.Close()
	})
	go func() {
		if err := worker.Run(ctx); err != nil {
			logger.Error("profile inbox consumer stopped", zap.Error(err))
		}
	}()
}

func envPositiveInt(key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
