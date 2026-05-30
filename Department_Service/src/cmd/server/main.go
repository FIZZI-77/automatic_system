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

	"department/pkg"
	"department/src/core/handler"
	"department/src/core/repository"
	"department/src/core/service"

	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
)

func main() {
	logger, err := pkg.NewLogger()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	if err = godotenv.Load(".env"); err != nil {
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
	defer db.Close()

	grpcPort := os.Getenv("GRPC_PORT")
	if strings.TrimSpace(grpcPort) == "" {
		grpcPort = "50053"
	}

	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(pkg.RequestIDUnaryServerInterceptor))
	repo := repository.NewRepository(db)
	departmentService := service.NewService(repo, logger)
	departmentHandler := handler.NewDepartmentHandler(departmentService, logger)
	departmentv1.RegisterDepartmentServiceServer(grpcServer, departmentHandler)

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
		log.Fatalf("grpc server failed: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	log.Println("department service stopped")
}
