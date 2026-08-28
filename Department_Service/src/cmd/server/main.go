package main

import (
	"context"
	"department/pkg/telemetry"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"department/pkg"
	"department/pkg/closer"
	appconfig "department/pkg/config"
	"department/src/core/handler"
	"department/src/core/repository"
	"department/src/core/service"

	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	telemetryProviders, err := telemetry.Init(context.Background(), "department-service")
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

	if err = godotenv.Load(".env"); err != nil && !os.IsNotExist(err) {
		log.Fatal("error loading .env file")
	}

	dbConfig := pkg.Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		Username: os.Getenv("DB_USERNAME"),
		Password: os.Getenv("DB_PASSWORD"),
		DbName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("SSLMODE"),
	}
	writeDB, err := pkg.NewPostgresDB(dbConfig)
	if err != nil {
		log.Fatalf("failed to connect db: %v", err)
	}
	dependencies.Add("postgres", func() error {
		writeDB.Close()
		return nil
	})
	readHost := strings.TrimSpace(os.Getenv("DB_READ_HOST"))
	if readHost == "" {
		readHost = dbConfig.Host
	}
	dbConfig.Host = readHost
	readDB, err := pkg.NewPostgresDB(dbConfig)
	if err != nil {
		log.Fatalf("failed to connect read db: %v", err)
	}
	dependencies.Add("postgres read", func() error {
		readDB.Close()
		return nil
	})
	defer closeDependencies(dependencies)
	startOutboxRelay(writeDB, dependencies, logger)

	grpcPort := os.Getenv("GRPC_PORT")
	if strings.TrimSpace(grpcPort) == "" {
		grpcPort = "50053"
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
	departmentService := service.NewService(repo, logger)
	departmentHandler := handler.NewDepartmentHandler(departmentService, logger)
	departmentv1.RegisterDepartmentServiceServer(grpcServer, departmentHandler)
	healthv1.RegisterHealthServer(grpcServer, health.NewServer())

	serverErrCh := make(chan error, 1)
	go func() {
		log.Printf("department service listening at %v", lis.Addr())
		if err = grpcServer.Serve(lis); err != nil {
			serverErrCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("received signal: %v", sig)
	case err = <-serverErrCh:
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

	log.Println("department service stopped")
}

func closeDependencies(dependencies *closer.Closer) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := dependencies.Close(ctx); err != nil {
		log.Printf("failed to close dependencies: %v", err)
	}
}
