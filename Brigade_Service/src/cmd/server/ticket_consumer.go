package main

import (
	"context"
	"os"
	"strings"

	"brigade/pkg/closer"
	"brigade/src/infrastructure/ticketconsumer"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func startTicketConsumer(db *pgxpool.Pool, dependencies *closer.Closer, logger *zap.Logger) {
	raw := strings.TrimSpace(os.Getenv("KAFKA_BROKERS"))
	if raw == "" {
		logger.Warn("ticket consumer disabled: KAFKA_BROKERS is empty")
		return
	}
	worker, err := ticketconsumer.New(db, ticketconsumer.Config{
		Brokers: strings.Split(raw, ","),
		Topic:   envOrDefault("KAFKA_TICKET_TOPIC", "tickets.events.v1"),
		GroupID: envOrDefault("TICKET_CONSUMER_GROUP_ID", "brigade-ticket-lifecycle-v1"),
		Workers: envPositiveInt("TICKET_CONSUMER_WORKERS", 2),
	}, logger)
	if err != nil {
		logger.Fatal("failed to initialize ticket consumer", zap.Error(err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	dependencies.Add("ticket consumer", func() error { cancel(); return worker.Close() })
	go func() {
		if err := worker.Run(ctx); err != nil {
			logger.Error("ticket consumer stopped", zap.Error(err))
		}
	}()
}
