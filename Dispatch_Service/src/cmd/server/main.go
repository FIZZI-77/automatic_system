package main

import (
	"context"
	"dispatch/pkg/telemetry"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	appconfig "dispatch/pkg/config"
	"dispatch/src/core/handler"
	"dispatch/src/core/repository"
	"dispatch/src/core/service"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	dispatchv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/dispatch/v1"
	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	telemetryProviders, err := telemetry.Init(context.Background(), "dispatch-service")
	if err != nil {
		log.Fatalf("initialize OpenTelemetry: %v", err)
	}
	defer func() {
		if shutdownErr := telemetryProviders.Close(); shutdownErr != nil {
			log.Printf("shutdown OpenTelemetry: %v", shutdownErr)
		}
	}()

	if err := appconfig.Load(); err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	databaseURL := required("DATABASE_URL")
	writeDB, err := telemetry.NewPostgresPool(ctx, databaseURL, int32(integer("DATABASE_MAX_CONNECTIONS", 8)))
	if err != nil {
		log.Fatal(err)
	}
	defer writeDB.Close()
	if err = writeDB.Ping(ctx); err != nil {
		log.Fatal(err)
	}
	readDB, err := telemetry.NewPostgresPool(ctx, env("READ_DATABASE_URL", databaseURL), int32(integer("READ_DATABASE_MAX_CONNECTIONS", 4)))
	if err != nil {
		log.Fatal(err)
	}
	defer readDB.Close()
	if err = readDB.Ping(ctx); err != nil {
		log.Fatal(err)
	}
	lockDB, err := telemetry.NewPostgresPool(ctx, databaseURL, int32(integer("LOCK_DATABASE_MAX_CONNECTIONS", 4)))
	if err != nil {
		log.Fatal(err)
	}
	defer lockDB.Close()
	if err = lockDB.Ping(ctx); err != nil {
		log.Fatal(err)
	}
	dependencyTimeout := duration("DEPENDENCY_TIMEOUT", 10*time.Second)
	dial := func(address string) *grpc.ClientConn {
		connection, dialErr := grpc.NewClient(
			address,
			telemetry.GRPCClientOption(),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithChainUnaryInterceptor(defaultTimeoutInterceptor(dependencyTimeout)),
		)
		if dialErr != nil {
			log.Fatal(dialErr)
		}
		return connection
	}
	ticketConn := dial(env("TICKET_SERVICE_ADDR", "ticket-service:50052"))
	defer ticketConn.Close()
	brigadeConn := dial(env("BRIGADE_SERVICE_ADDR", "brigade-service:50054"))
	defer brigadeConn.Close()
	locationConn := dial(env("LOCATION_SERVICE_ADDR", "location-service:50056"))
	defer locationConn.Close()
	routingConn := dial(env("ROUTING_SERVICE_ADDR", "routing-service:50057"))
	defer routingConn.Close()
	dependencies := service.Dependencies{
		Tickets:  ticketv1.NewTicketServiceClient(ticketConn),
		Brigades: brigadev1.NewBrigadeServiceClient(brigadeConn),
		Location: locationv1.NewLocationServiceClient(locationConn),
		Routing:  routingv1.NewRoutingServiceClient(routingConn),
	}
	value, err := service.New(
		repository.NewWithLockPool(writeDB, readDB, lockDB),
		dependencies,
		duration("RESERVATION_TTL", 2*time.Minute),
		logger,
	)
	if err != nil {
		log.Fatal(err)
	}
	workerCtx, cancelWorker := context.WithCancel(ctx)
	defer cancelWorker()
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		cleanupLoop(workerCtx, value, duration("CLEANUP_INTERVAL", 15*time.Second), logger)
	}()
	outboxWorker := startOutboxRelay(workerCtx, writeDB, &workers, logger)
	if outboxWorker != nil {
		defer outboxWorker.Close()
	}
	ticketConsumer := startTicketConsumer(workerCtx, value, &workers, logger)
	if ticketConsumer != nil {
		defer ticketConsumer.Close()
	}
	listener, err := net.Listen("tcp", ":"+env("GRPC_PORT", "50058"))
	if err != nil {
		log.Fatal(err)
	}
	server := grpc.NewServer(telemetry.GRPCServerOption())
	dispatchv1.RegisterDispatchServiceServer(server, handler.New(value))
	healthv1.RegisterHealthServer(server, health.NewServer())
	go func() {
		logger.Info("dispatch gRPC started", zap.String("address", listener.Addr().String()))
		if serveErr := server.Serve(listener); serveErr != nil {
			logger.Error("dispatch gRPC failed", zap.Error(serveErr))
			stop()
		}
	}()
	<-ctx.Done()
	cancelWorker()
	stopGRPCServer(server, duration("SHUTDOWN_TIMEOUT", 25*time.Second), logger)
	workers.Wait()
}

func defaultTimeoutInterceptor(timeout time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, request, reply any, connection *grpc.ClientConn, invoke grpc.UnaryInvoker, options ...grpc.CallOption) error {
		if _, hasDeadline := ctx.Deadline(); hasDeadline {
			return invoke(ctx, method, request, reply, connection, options...)
		}
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return invoke(callCtx, method, request, reply, connection, options...)
	}
}

func stopGRPCServer(server *grpc.Server, timeout time.Duration, logger *zap.Logger) {
	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-stopped:
		return
	case <-timer.C:
		logger.Warn("dispatch gRPC graceful shutdown timed out", zap.Duration("timeout", timeout))
		server.Stop()
		<-stopped
	}
}
func cleanupLoop(ctx context.Context, value *service.Service, interval time.Duration, logger *zap.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := value.Cleanup(ctx); err != nil {
				logger.Error("cleanup expired reservations", zap.Error(err))
			}
		}
	}
}
func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func required(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("%s is required", key)
	}
	return value
}
func duration(key string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(os.Getenv(key))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
