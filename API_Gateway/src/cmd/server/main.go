package main

import (
	"context"
	"errors"
	"gateway/pkg/closer"
	"gateway/src/core/handlers"
	"gateway/src/core/middleware"
	"gateway/src/core/requestid"
	authv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/auth/v1"
	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	dependencies := closer.New()

	authServiceAddr := getEnv("AUTH_SERVICE_ADDR", "localhost:50051")
	ticketServiceAddr := getEnv("TICKET_SERVICE_ADDR", "localhost:50052")
	departmentServiceAddr := getEnv("DEPARTMENT_SERVICE_ADDR", "localhost:50053")
	gatewayAddr := getEnv("GATEWAY_ADDR", ":8080")
	publicKeyPath := getEnv("JWT_PUBLIC_KEY_PATH", "./keys/public.pem")

	authConn, err := grpc.NewClient(
		authServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(requestid.UnaryClientInterceptor),
	)
	if err != nil {
		log.Fatalf("failed to connect to auth service: %v", err)
	}
	dependencies.Add("auth grpc connection", authConn.Close)
	defer closeDependencies(dependencies)

	authClient := authv1.NewAuthServiceClient(authConn)

	ticketConn, err := grpc.NewClient(
		ticketServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(requestid.UnaryClientInterceptor),
	)
	if err != nil {
		log.Fatalf("failed to connect to ticket service: %v", err)
	}
	dependencies.Add("ticket grpc connection", ticketConn.Close)

	ticketClient := ticketv1.NewTicketServiceClient(ticketConn)

	departmentConn, err := grpc.NewClient(
		departmentServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(requestid.UnaryClientInterceptor),
	)
	if err != nil {
		log.Fatalf("failed to connect to department service: %v", err)
	}
	dependencies.Add("department grpc connection", departmentConn.Close)

	departmentClient := departmentv1.NewDepartmentServiceClient(departmentConn)

	authMiddleware, err := middleware.NewAuthMiddleware(
		publicKeyPath,
		"auth-jwt",
		"api-gateway",
	)
	if err != nil {
		log.Fatalf("failed to init auth middleware: %v", err)
	}

	authHandler := handlers.NewAuthHandler(authClient)
	ticketHandler := handlers.NewTicketHandler(ticketClient)
	departmentHandler := handlers.NewDepartmentHandler(departmentClient)
	handler := handlers.NewHandler(authHandler, ticketHandler, departmentHandler, authMiddleware)
	router := handler.InitRouters()

	server := &http.Server{
		Addr:         gatewayAddr,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serverErrCh := make(chan error, 1)

	go func() {
		log.Printf("api gateway started on %s", gatewayAddr)
		log.Printf("auth service address: %s", authServiceAddr)
		log.Printf("ticket service address: %s", ticketServiceAddr)
		log.Printf("department service address: %s", departmentServiceAddr)

		if err = server.ListenAndServe(); err != nil && !errors.Is(http.ErrServerClosed, err) {
			serverErrCh <- err
		}
	}()

	quit := make(chan os.Signal, 1)

	signal.Notify(
		quit,
		syscall.SIGINT,
		syscall.SIGTERM,
	)

	select {
	case sig := <-quit:
		log.Printf("received signal: %v", sig)
	case err := <-serverErrCh:
		log.Printf("api gateway failed: %v", err)
		return
	}

	log.Println("shutting down api gateway...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err = server.Shutdown(ctx); err != nil {
		log.Printf("failed to shutdown http server gracefully: %v", err)
	}

	closeDependencies(dependencies)

	log.Println("api gateway stopped")
}

func closeDependencies(dependencies *closer.Closer) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := dependencies.Close(ctx); err != nil {
		log.Printf("failed to close dependencies: %v", err)
	}
}

func getEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	return value
}
