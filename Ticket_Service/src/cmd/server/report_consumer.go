package main

import (
	"context"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"ticket/pkg/closer"
	"ticket/src/infrastructure/reportconsumer"
)

func startReportConsumer(db *pgxpool.Pool, dependencies *closer.Closer, logger *zap.Logger) {
	brokers := splitRoutingBrokers(os.Getenv("KAFKA_BROKERS"))
	if len(brokers) == 0 {
		logger.Warn("report result consumer disabled: KAFKA_BROKERS is empty")
		return
	}
	worker, err := reportconsumer.New(
		db,
		brokers,
		envRouting("KAFKA_REPORT_TOPIC", "reports.events.v1"),
		envRouting("REPORT_RESULT_CONSUMER_GROUP_ID", "ticket-report-result-v1"),
		logger,
	)
	if err != nil {
		logger.Fatal("failed to initialize report result consumer", zap.Error(err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	dependencies.Add("report result consumer", func() error { cancel(); return worker.Close() })
	go func() {
		if err := worker.Run(ctx); err != nil {
			logger.Error("report result consumer stopped", zap.Error(err))
		}
	}()
}
