package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"ticket/pkg/telemetry"
	"time"

	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"ticket/pkg"
	"ticket/pkg/closer"
	appconfig "ticket/pkg/config"
	"ticket/src/core/handler"
	"ticket/src/core/repository"
	"ticket/src/core/service"
)

func main() {
	telemetryProviders, err := telemetry.Init(context.Background(), "ticket-service")
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

	writeDB, err := pkg.NewPostgresDB(pkg.Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		Username: os.Getenv("DB_USERNAME"),
		Password: os.Getenv("DB_PASSWORD"),
		DbName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("SSLMODE"),
		MaxConns: poolSize("DB_WRITE_MAX_CONNS", 16),
		MinConns: poolSize("DB_WRITE_MIN_CONNS", 2),
	})
	if err != nil {
		log.Fatalf("failed to connect primary db: %v", err)
	}
	readHost := strings.TrimSpace(os.Getenv("DB_READ_HOST"))
	if readHost == "" {
		readHost = os.Getenv("DB_HOST")
	}
	readDB, err := pkg.NewPostgresDB(pkg.Config{
		Host:     readHost,
		Port:     os.Getenv("DB_PORT"),
		Username: os.Getenv("DB_USERNAME"),
		Password: os.Getenv("DB_PASSWORD"),
		DbName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("SSLMODE"),
		MaxConns: poolSize("DB_READ_MAX_CONNS", 16),
		MinConns: poolSize("DB_READ_MIN_CONNS", 2),
	})
	if err != nil {
		writeDB.Close()
		log.Fatalf("failed to connect read replica: %v", err)
	}
	dependencies.Add("postgres primary", func() error {
		writeDB.Close()
		return nil
	})
	dependencies.Add("postgres replica", func() error {
		readDB.Close()
		return nil
	})
	defer closeDependencies(dependencies)
	startOutboxRelay(writeDB, dependencies, logger)
	startRoutingConsumer(writeDB, dependencies, logger)
	startReportConsumer(writeDB, dependencies, logger)
	startCompletionSaga(writeDB, dependencies, logger)
	startTicketRetention(writeDB, dependencies, logger)

	grpcPort := os.Getenv("GRPC_PORT")
	if strings.TrimSpace(grpcPort) == "" {
		grpcPort = "50052"
	}

	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(
		telemetry.GRPCServerOption(),
		grpc.ChainUnaryInterceptor(
			pkg.RequestIDUnaryServerInterceptor,
			pkg.IdempotencyKeyUnaryServerInterceptor,
			pkg.AccessLogUnaryServerInterceptor(logger),
		),
	)

	repo := repository.NewRepository(repository.DBPools{Write: writeDB, Read: readDB})
	ticketService := service.NewService(repo, logger)
	ticketHandler := handler.NewTicketHandler(ticketService, logger)

	ticketv1.RegisterTicketServiceServer(grpcServer, ticketHandler)
	healthv1.RegisterHealthServer(grpcServer, health.NewServer())

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

func poolSize(name string, fallback int32) int32 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}

	value, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || value < 0 {
		log.Printf("invalid %s=%q; using %d", name, raw, fallback)
		return fallback
	}

	return int32(value)
}

func closeDependencies(dependencies *closer.Closer) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := dependencies.Close(ctx); err != nil {
		log.Printf("failed to close dependencies: %v", err)
	}
}
