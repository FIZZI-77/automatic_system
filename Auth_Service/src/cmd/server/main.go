package main

import (
	"auth/pkg"
	"auth/pkg/closer"
	"auth/src/core/handler"
	"auth/src/core/repository"
	"auth/src/core/service"
	"context"
	v1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/auth/v1"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	dependencies := closer.New()

	logger, err := pkg.NewLogger()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	err = godotenv.Load(".env")
	if err != nil {
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

	privateKey, err := pkg.LoadRSAPrivateKey(os.Getenv("JWT_PRIVATE_KEY_PATH"))
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	keyID := os.Getenv("JWT_KEY_ID")
	if keyID == "" {
		log.Fatal("JWT_KEY_ID is empty")
	}

	lis, err := net.Listen("tcp", ":50051")
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
	mailService, err := service.NewSMTPMailService(service.SMTPMailConfig{
		Host:            os.Getenv("SMTP_HOST"),
		Port:            mustInt(os.Getenv("SMTP_PORT")),
		Username:        os.Getenv("SMTP_USERNAME"),
		Password:        os.Getenv("SMTP_PASSWORD"),
		FromEmail:       os.Getenv("SMTP_FROM_EMAIL"),
		FromName:        os.Getenv("SMTP_FROM_NAME"),
		FrontendBaseURL: os.Getenv("FRONTEND_BASE_URL"),
		UseTLS:          mustBool(os.Getenv("SMTP_USE_TLS")),
		UseStartTLS:     mustBool(os.Getenv("SMTP_USE_STARTTLS")),
		Timeout:         10 * time.Second,
	}, logger)

	if err != nil {
		log.Fatalf("failed to init mail jwt: %v", err)
	}
	authService := service.NewService(repo, privateKey, keyID, mailService, logger)
	authHandler := handler.NewAuthHandler(authService, logger)

	v1.RegisterAuthServiceServer(grpcServer, authHandler)

	serverErrCh := make(chan error, 1)

	go func() {
		log.Printf("server listening at %v", lis.Addr())
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

	log.Println("application stopped")
}

func closeDependencies(dependencies *closer.Closer) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := dependencies.Close(ctx); err != nil {
		log.Printf("failed to close dependencies: %v", err)
	}
}

func mustInt(value string) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		log.Fatalf("invalid int value %q: %v", value, err)
	}
	return n
}

func mustBool(value string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		log.Fatalf("invalid bool value %q: %v", value, err)
	}
	return b
}
