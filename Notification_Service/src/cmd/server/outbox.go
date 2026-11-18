package main

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
	"notification/src/infrastructure/outboxrelay"
)

// startOutboxRelay returns a shutdown hook that waits before closing the writer.
func startOutboxRelay(ctx context.Context, db *pgxpool.Pool, logger *zap.Logger) func() {
	brokers := make([]string, 0)
	for _, broker := range strings.Split(must("KAFKA_BROKERS"), ",") {
		if broker = strings.TrimSpace(broker); broker != "" {
			brokers = append(brokers, broker)
		}
	}
	if len(brokers) == 0 {
		logger.Fatal("KAFKA_BROKERS must contain a broker")
	}
	writer := &kafka.Writer{
		Addr: kafka.TCP(brokers...), Topic: "notifications.events.v1",
		Balancer: &kafka.Hash{}, RequiredAcks: kafka.RequireAll,
		WriteTimeout: 10 * time.Second,
	}
	worker := outboxrelay.New(db, writer, logger)
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		worker.Run(workerCtx)
	}()
	return func() {
		cancel()
		<-done
		if err := writer.Close(); err != nil {
			logger.Error("close outbox writer", zap.Error(err))
		}
	}
}
