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
	"ticket/src/core/handler"
	"ticket/src/core/repository"
	"ticket/src/core/service"

	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
)

func main() {

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

	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("failed to close db: %v", err)
		}
	}()

	grpcPort := os.Getenv("GRPC_PORT")
	if strings.TrimSpace(grpcPort) == "" {
		grpcPort = "50052"
	}

	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()

	repo := repository.NewRepository(db)
	ticketService := service.NewService(repo, logger)
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

	log.Println("ticket service stopped")
}
