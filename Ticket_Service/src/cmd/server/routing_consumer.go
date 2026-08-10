package main

import (
	"context"
	"os"
	"strconv"
	"strings"

	"ticket/pkg/closer"
	"ticket/src/infrastructure/routingconsumer"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func startRoutingConsumer(db *pgxpool.Pool, dependencies *closer.Closer, logger *zap.Logger) {
	brokers := splitRoutingBrokers(os.Getenv("KAFKA_BROKERS"))
	if len(brokers) == 0 {
		logger.Warn("routing consumer disabled: KAFKA_BROKERS is empty")
		return
	}
	worker, err := routingconsumer.New(db, routingconsumer.Config{
		Brokers: brokers,
		Topic:   envRouting("KAFKA_ROUTING_TOPIC", "routing.events.v1"),
		GroupID: envRouting("ROUTING_CONSUMER_GROUP_ID", "ticket-routing-projection-v1"),
		Workers: envRoutingInt("ROUTING_CONSUMER_WORKERS", 2),
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

func envRouting(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envRoutingInt(key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func splitRoutingBrokers(value string) []string {
	result := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
