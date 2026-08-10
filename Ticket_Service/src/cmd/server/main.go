package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ticket/pkg"
	"ticket/pkg/closer"
	"ticket/src/core/handler"
	"ticket/src/core/repository"
	"ticket/src/core/service"
	"ticket/src/infrastructure/assignmentrouting"

	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	dependencies := closer.New()

	logger, err := pkg.NewLogger()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	err = godotenv.Load(".env")
	if err != nil && !os.IsNotExist(err) {
		log.Fatal("error loading .env file")
	}

	db, err := pkg.NewPostgresDB(pkg.Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		Username: os.Getenv("DB_USERNAME"),
		Password: os.Getenv("DB_PASSWORD"),
		DbName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("SSLMODE"),
	})
	if err != nil {
		log.Fatalf("failed to connect db: %v", err)
	}
	dependencies.Add("postgres", func() error {
		db.Close()
		return nil
	})
	defer closeDependencies(dependencies)
	startOutboxRelay(db, dependencies, logger)
	startRoutingConsumer(db, dependencies, logger)

	locationConn, err := grpc.NewClient(envRouting("LOCATION_SERVICE_ADDR", "localhost:50056"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to create location grpc client: %v", err)
	}
	dependencies.Add("location grpc", locationConn.Close)
	routingConn, err := grpc.NewClient(envRouting("ROUTING_SERVICE_ADDR", "localhost:50057"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to create routing grpc client: %v", err)
	}
	dependencies.Add("routing grpc", routingConn.Close)
	routeCreator, err := assignmentrouting.New(locationv1.NewLocationServiceClient(locationConn), routingv1.NewRoutingServiceClient(routingConn))
	if err != nil {
		log.Fatalf("failed to create assignment routing client: %v", err)
	}
	grpcPort := os.Getenv("GRPC_PORT")
	if strings.TrimSpace(grpcPort) == "" {
		grpcPort = "50052"
	}

	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			pkg.RequestIDUnaryServerInterceptor,
			pkg.IdempotencyKeyUnaryServerInterceptor,
			pkg.AccessLogUnaryServerInterceptor(logger),
		),
	)

	repo := repository.NewRepository(repository.DBPools{Write: db, Read: db})
	ticketService := service.NewServiceWithRouteCreator(repo, routeCreator, logger)
	ticketHandler := handler.NewTicketHandler(ticketService, logger)

	ticketv1.RegisterTicketServiceServer(grpcServer, ticketHandler)

	serverErrCh := make(chan error, 1)

	go func() {
		log.Printf("ticket service listening at %v", lis.Addr())

		if err := grpcServer.Serve(lis); err != nil {
			serverErrCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("received signal: %v", sig)
	case err := <-serverErrCh:
		log.Printf("grpc server failed: %v", err)
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	done := make(chan struct{})

	go func() {
		grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		log.Println("grpc server stopped gracefully")
	case <-shutdownCtx.Done():
		log.Println("graceful shutdown timed out, forcing stop")
		grpcServer.Stop()
	}

	closeDependencies(dependencies)

	log.Println("ticket service stopped")
}

func closeDependencies(dependencies *closer.Closer) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := dependencies.Close(ctx); err != nil {
		log.Printf("failed to close dependencies: %v", err)
	}
}
