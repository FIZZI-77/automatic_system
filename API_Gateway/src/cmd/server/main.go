package main

import (
	authv1 "auth/auth/v1"
	"context"
	"errors"
	"gateway/src/core/handlers"
	"gateway/src/core/middleware"
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
	authServiceAddr := getEnv("AUTH_SERVICE_ADDR", "localhost:50051")
	gatewayAddr := getEnv("GATEWAY_ADDR", ":8080")
	publicKeyPath := getEnv("JWT_PUBLIC_KEY_PATH", "./keys/public.pem")

	authConn, err := grpc.NewClient(
		authServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("failed to connect to auth service: %v", err)
	}

	authClient := authv1.NewAuthServiceClient(authConn)

	authMiddleware, err := middleware.NewAuthMiddleware(
		publicKeyPath,
		"auth-jwt",
		"api-gateway",
	)
	if err != nil {
		log.Fatalf("failed to init auth middleware: %v", err)
	}

	authHandler := handlers.NewAuthHandler(authClient)
	handler := handlers.NewHandler(authHandler, authMiddleware)
	router := handler.InitRouters()

	server := &http.Server{
		Addr:         gatewayAddr,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("api gateway started on %s", gatewayAddr)
		log.Printf("auth service address: %s", authServiceAddr)

		if err = server.ListenAndServe(); err != nil && !errors.Is(http.ErrServerClosed, err) {
			log.Fatalf("failed to start api gateway: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)

	signal.Notify(
		quit,
		syscall.SIGINT,
		syscall.SIGTERM,
	)

	<-quit

	log.Println("shutting down api gateway...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err = server.Shutdown(ctx); err != nil {
		log.Printf("failed to shutdown http server gracefully: %v", err)
	}

	if err = authConn.Close(); err != nil {
		log.Printf("failed to close auth grpc connection: %v", err)
	}

	log.Println("api gateway stopped")
}

func getEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	return value
}
