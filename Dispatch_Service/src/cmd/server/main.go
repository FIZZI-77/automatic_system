package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dispatch/src/core/handler"
	"dispatch/src/core/repository"
	"dispatch/src/core/service"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	dispatchv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/dispatch/v1"
	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	db, err := pgxpool.New(ctx, required("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err = db.Ping(ctx); err != nil {
		log.Fatal(err)
	}
	dial := func(address string) *grpc.ClientConn {
		connection, dialErr := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
	value, err := service.New(repository.New(db), service.Dependencies{Tickets: ticketv1.NewTicketServiceClient(ticketConn), Brigades: brigadev1.NewBrigadeServiceClient(brigadeConn), Location: locationv1.NewLocationServiceClient(locationConn), Routing: routingv1.NewRoutingServiceClient(routingConn)}, duration("RESERVATION_TTL", 2*time.Minute), logger)
	if err != nil {
		log.Fatal(err)
	}
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	defer cancelWorker()
	go cleanupLoop(workerCtx, value, duration("CLEANUP_INTERVAL", 15*time.Second), logger)
	listener, err := net.Listen("tcp", ":"+env("GRPC_PORT", "50058"))
	if err != nil {
		log.Fatal(err)
	}
	server := grpc.NewServer()
	dispatchv1.RegisterDispatchServiceServer(server, handler.New(value))
	go func() {
		logger.Info("dispatch gRPC started", zap.String("address", listener.Addr().String()))
		if serveErr := server.Serve(listener); serveErr != nil {
			logger.Error("dispatch gRPC failed", zap.Error(serveErr))
			stop()
		}
	}()
	<-ctx.Done()
	cancelWorker()
	server.GracefulStop()
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
