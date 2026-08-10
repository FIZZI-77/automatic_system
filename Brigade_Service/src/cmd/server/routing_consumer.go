package main

import (
	"context"
	"os"
	"strings"

	"brigade/pkg/closer"
	"brigade/src/infrastructure/routingconsumer"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func startRoutingConsumer(db *pgxpool.Pool, dependencies *closer.Closer, logger *zap.Logger) {
	raw := strings.TrimSpace(os.Getenv("KAFKA_BROKERS"))
	if raw == "" {
		logger.Warn("routing consumer disabled: KAFKA_BROKERS is empty")
		return
	}
	worker, err := routingconsumer.New(db, routingconsumer.Config{
		Brokers: strings.Split(raw, ","),
		Topic:   envOrDefault("KAFKA_ROUTING_TOPIC", "routing.events.v1"),
		GroupID: envOrDefault("ROUTING_CONSUMER_GROUP_ID", "brigade-routing-projection-v1"),
		Workers: envPositiveInt("ROUTING_CONSUMER_WORKERS", 2),
	}, logger)
	if err != nil {
		logger.Fatal("failed to initialize routing consumer", zap.Error(err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	dependencies.Add("routing consumer", func() error { cancel(); return worker.Close() })
	go func() {
		if err := worker.Run(ctx); err != nil {
			logger.Error("routing consumer stopped", zap.Error(err))
		}
	}()
}
