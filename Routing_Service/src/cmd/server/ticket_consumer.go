package main

import (
	"context"
	"os"

	"routing/pkg/closer"
	"routing/src/infrastructure/ticketconsumer"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func startTicketConsumer(db *pgxpool.Pool, dependencies *closer.Closer, logger *zap.Logger) {
	brokers := split(os.Getenv("KAFKA_BROKERS"))
	if len(brokers) == 0 {
		logger.Warn("ticket consumer disabled: KAFKA_BROKERS is empty")
		return
	}
	worker, err := ticketconsumer.New(db, ticketconsumer.Config{
		Brokers: brokers,
		Topic:   env("KAFKA_TICKET_TOPIC", "tickets.events.v1"),
		GroupID: env("TICKET_CONSUMER_GROUP_ID", "routing-ticket-lifecycle-v1"),
		Workers: envInt("TICKET_CONSUMER_WORKERS", 2),
	}, logger)
	if err != nil {
		fatalWithCleanup(logger, dependencies, "create ticket consumer", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	dependencies.Add("ticket consumer", func() error { cancel(); return worker.Close() })
	go func() {
		if err := worker.Run(ctx); err != nil {
			logger.Error("ticket consumer stopped", zap.Error(err))
		}
	}()
}
