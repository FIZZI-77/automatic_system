package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"profile/pkg/telemetry"
	"strings"
	"syscall"
	"time"

	authv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/auth/v1"
	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"

	"profile/pkg"
	"profile/pkg/closer"
	appconfig "profile/pkg/config"
	"profile/src/core/handler"
	"profile/src/core/repository"
	"profile/src/core/service"
	"profile/src/infrastructure/grpcdeps"
)

func main() {
	telemetryProviders, err := telemetry.Init(context.Background(), "profile-service")
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

	if err = loadEnvFile(".env"); err != nil && !os.IsNotExist(err) {
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

	authConn, err := newGRPCClient(
		envOrDefault("AUTH_GRPC_ADDR", "localhost:50051"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(pkg.RequestIDUnaryClientInterceptor),
	)
	if err != nil {
		log.Fatalf("failed to create auth grpc client: %v", err)
	}
	dependencies.Add("auth grpc", authConn.Close)

	departmentConn, err := newGRPCClient(
		envOrDefault("DEPARTMENT_GRPC_ADDR", "localhost:50053"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(pkg.RequestIDUnaryClientInterceptor),
	)
	if err != nil {
		log.Fatalf("failed to create department grpc client: %v", err)
	}
	dependencies.Add("department grpc", departmentConn.Close)

	grpcPort := envOrDefault("GRPC_PORT", "50055")
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
	profileService := service.NewService(repo, service.Dependencies{
		UserAccountChecker: grpcdeps.NewUserChecker(authv1.NewAuthServiceClient(authConn)),
		DepartmentChecker:  grpcdeps.NewDepartmentChecker(departmentv1.NewDepartmentServiceClient(departmentConn)),
	}, logger)
	startCertificationExpiryWorker(profileService.CertificationService, dependencies, logger)
	profileHandler := handler.NewProfileHandler(profileService, logger)

	profilev1.RegisterProfileServiceServer(grpcServer, profileHandler)
	healthv1.RegisterHealthServer(grpcServer, health.NewServer())

	serverErrCh := make(chan error, 1)
	go func() {
		log.Printf("profile service listening at %v", lis.Addr())
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
	log.Println("profile service stopped")
}

func envOrDefault(key string, defaultValue string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	return value
}

func loadEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("invalid env line: %q", line)
		}

		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if key == "" {
			return fmt.Errorf("empty env key")
		}

		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, value); err != nil {
				return err
			}
		}
	}

	return scanner.Err()
}

func closeDependencies(dependencies *closer.Closer) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := dependencies.Close(ctx); err != nil {
		log.Printf("failed to close dependencies: %v", err)
	}
}

func newGRPCClient(target string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
	options = append([]grpc.DialOption{telemetry.GRPCClientOption()}, options...)
	return grpc.NewClient(target, options...)
}
