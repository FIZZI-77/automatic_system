package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"brigade/pkg"
	"brigade/pkg/closer"
	"brigade/src/core/handler"
	"brigade/src/core/repository"
	"brigade/src/core/service"
)

func main() {
	dependencies := closer.New()

	logger, err := pkg.NewLogger()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	if err = loadEnvFile(".env"); err != nil {
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

	departmentConn, err := grpc.NewClient(
		envOrDefault("DEPARTMENT_GRPC_ADDR", "localhost:50053"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(
			pkg.RequestIDUnaryClientInterceptor,
		),
	)
	if err != nil {
		log.Fatalf("failed to create department grpc client: %v", err)
	}
	dependencies.Add("department grpc", departmentConn.Close)

	grpcPort := envOrDefault("GRPC_PORT", "50054")
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
	departmentClient := departmentv1.NewDepartmentServiceClient(departmentConn)
	brigadeService := service.NewService(repo, departmentClient, logger)
	brigadeHandler := handler.NewBrigadeHandler(brigadeService, logger)

	brigadev1.RegisterBrigadeServiceServer(grpcServer, brigadeHandler)

	serverErrCh := make(chan error, 1)
	go func() {
		log.Printf("brigade service listening at %v", lis.Addr())
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
	log.Println("brigade service stopped")
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
