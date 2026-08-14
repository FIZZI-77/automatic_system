package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"audit/pkg"
	appconfig "audit/pkg/config"
	"audit/src/core/handler"
	"audit/src/core/repository"
	"audit/src/core/service"
	"audit/src/infrastructure/eventconsumer"
	auditv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/audit/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	if err := appconfig.Load(); err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger, err := pkg.NewLogger()
	if err != nil {
		log.Fatal(err)
	}
	defer logger.Sync()
	db, err := pgxpool.New(ctx, required("DATABASE_URL"))
	if err != nil {
		logger.Fatal("database failed", zap.Error(err))
	}
	defer db.Close()
	if err = db.Ping(ctx); err != nil {
		logger.Fatal("database unavailable", zap.Error(err))
	}
	repo := repository.NewRepository(db)
	svc := service.NewService(repo)
	brokers := split(required("KAFKA_BROKERS"))
	workers := make([]*eventconsumer.Worker, 0)
	for _, topic := range split(required("KAFKA_TOPICS")) {
		worker := eventconsumer.New(brokers, topic, env("KAFKA_GROUP", "audit-service"), svc, logger)
		workers = append(workers, worker)
		go run(ctx, "consumer "+topic, worker.Run, logger)
	}
	defer func() {
		for _, worker := range workers {
			_ = worker.Close()
		}
	}()
	listener, err := net.Listen("tcp", ":"+env("GRPC_PORT", "50062"))
	if err != nil {
		logger.Fatal("listen failed", zap.Error(err))
	}
	server := grpc.NewServer()
	auditv1.RegisterAuditServiceServer(server, handler.New(svc))
	healthServer := health.NewServer()
	healthv1.RegisterHealthServer(server, healthServer)
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	go func() {
		logger.Info("audit gRPC started", zap.String("address", listener.Addr().String()))
		if err := server.Serve(listener); err != nil && ctx.Err() == nil {
			logger.Error("gRPC stopped", zap.Error(err))
			stop()
		}
	}()
	<-ctx.Done()
	healthServer.Shutdown()
	server.GracefulStop()
}

func run(ctx context.Context, name string, fn func(context.Context) error, logger *zap.Logger) {
	if err := fn(ctx); err != nil && ctx.Err() == nil {
		logger.Error(name+" stopped", zap.Error(err))
	}
}
func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
func required(key string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		log.Fatalf("%s is required", key)
	}
	return value
}
func split(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			result = append(result, value)
		}
	}
	return result
}
