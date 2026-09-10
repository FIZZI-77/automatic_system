package main

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"ticket/pkg/closer"
	"ticket/src/infrastructure/retentionworker"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func startTicketRetention(db *pgxpool.Pool, dependencies *closer.Closer, logger *zap.Logger) {
	if !envBool("TICKET_RETENTION_ENABLED", true) {
		logger.Info("ticket retention workers disabled")
		return
	}
	worker, err := retentionworker.New(db, retentionworker.Config{
		ArchiveAfter:    envDuration("TICKET_ARCHIVE_AFTER", 24*time.Hour),
		PurgeAfter:      envDuration("TICKET_PURGE_AFTER", 30*24*time.Hour),
		ArchiveInterval: envDuration("TICKET_ARCHIVE_INTERVAL", 5*time.Minute),
		PurgeInterval:   envDuration("TICKET_PURGE_INTERVAL", time.Hour),
		BatchSize:       envInt("TICKET_RETENTION_BATCH_SIZE", 100),
	}, logger)
	if err != nil {
		logger.Fatal("failed to initialize ticket retention workers", zap.Error(err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	dependencies.Add("ticket retention workers", func() error { cancel(); return nil })
	go func() {
		if err := worker.Run(ctx); err != nil {
			logger.Error("ticket retention workers stopped", zap.Error(err))
		}
	}()
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(strings.TrimSpace(os.Getenv(key)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
