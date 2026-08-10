package main

import (
	"context"
	"errors"
	"gateway/pkg/closer"
	"gateway/src/core/handlers"
	"gateway/src/core/idempotency"
	"gateway/src/core/middleware"
	"gateway/src/core/requestid"
	"gateway/src/core/retry"
	authv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/auth/v1"
	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	dispatchv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/dispatch/v1"
	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
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
	brigadeServiceAddr := getEnv("BRIGADE_SERVICE_ADDR", "localhost:50054")
	profileServiceAddr := getEnv("PROFILE_SERVICE_ADDR", "localhost:50055")
	locationServiceAddr := getEnv("LOCATION_SERVICE_ADDR", "localhost:50056")
	routingServiceAddr := getEnv("ROUTING_SERVICE_ADDR", "localhost:50057")
	dispatchServiceAddr := getEnv("DISPATCH_SERVICE_ADDR", "localhost:50058")
	gatewayAddr := getEnv("GATEWAY_ADDR", ":8080")
	publicKeyPath := getEnv("JWT_PUBLIC_KEY_PATH", "./keys/public.pem")

	authConn, err := grpc.NewClient(
		authServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(
			requestid.UnaryClientInterceptor,
			idempotency.UnaryClientInterceptor,
			retry.UnaryClientInterceptor,
		),
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
		grpc.WithChainUnaryInterceptor(
			requestid.UnaryClientInterceptor,
			idempotency.UnaryClientInterceptor,
			retry.UnaryClientInterceptor,
		),
	)
	if err != nil {
		log.Fatalf("failed to connect to ticket service: %v", err)
	}
	dependencies.Add("ticket grpc connection", ticketConn.Close)

	ticketClient := ticketv1.NewTicketServiceClient(ticketConn)

	departmentConn, err := grpc.NewClient(
		departmentServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(
			requestid.UnaryClientInterceptor,
			idempotency.UnaryClientInterceptor,
			retry.UnaryClientInterceptor,
		),
	)
	if err != nil {
		log.Fatalf("failed to connect to department service: %v", err)
	}
	dependencies.Add("department grpc connection", departmentConn.Close)

	departmentClient := departmentv1.NewDepartmentServiceClient(departmentConn)

	brigadeConn, err := grpc.NewClient(
		brigadeServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(
			requestid.UnaryClientInterceptor,
			idempotency.UnaryClientInterceptor,
			retry.UnaryClientInterceptor,
		),
	)
	if err != nil {
		log.Fatalf("failed to connect to brigade service: %v", err)
	}
	dependencies.Add("brigade grpc connection", brigadeConn.Close)

	brigadeClient := brigadev1.NewBrigadeServiceClient(brigadeConn)

	profileConn, err := grpc.NewClient(
		profileServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(
			requestid.UnaryClientInterceptor,
			idempotency.UnaryClientInterceptor,
			retry.UnaryClientInterceptor,
		),
	)
	if err != nil {
		log.Fatalf("failed to connect to profile service: %v", err)
	}
	dependencies.Add("profile grpc connection", profileConn.Close)

	profileClient := profilev1.NewProfileServiceClient(profileConn)

	locationConn, err := grpc.NewClient(
		locationServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(
			requestid.UnaryClientInterceptor,
			idempotency.UnaryClientInterceptor,
			retry.UnaryClientInterceptor,
		),
	)
	if err != nil {
		log.Fatalf("failed to connect to location service: %v", err)
	}
	dependencies.Add("location grpc connection", locationConn.Close)

	locationClient := locationv1.NewLocationServiceClient(locationConn)

	routingConn, err := grpc.NewClient(
		routingServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(
			requestid.UnaryClientInterceptor,
			idempotency.UnaryClientInterceptor,
			retry.UnaryClientInterceptor,
		),
	)
	if err != nil {
		log.Fatalf("failed to connect to routing service: %v", err)
	}
	dependencies.Add("routing grpc connection", routingConn.Close)

	routingClient := routingv1.NewRoutingServiceClient(routingConn)
	dispatchConn, err := grpc.NewClient(
		dispatchServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(requestid.UnaryClientInterceptor, idempotency.UnaryClientInterceptor, retry.UnaryClientInterceptor),
	)
	if err != nil {
		log.Fatalf("failed to connect to dispatch service: %v", err)
	}
	dependencies.Add("dispatch grpc connection", dispatchConn.Close)
	dispatchClient := dispatchv1.NewDispatchServiceClient(dispatchConn)

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
	brigadeHandler := handlers.NewBrigadeHandler(brigadeClient)
	profileHandler := handlers.NewProfileHandler(profileClient)
	locationHandler := handlers.NewLocationHandler(locationClient)
	routingHandler := handlers.NewRoutingHandler(routingClient)
	dispatchHandler := handlers.NewDispatchHandler(dispatchClient)
	handler := handlers.NewHandler(
		authHandler,
		ticketHandler,
		departmentHandler,
		brigadeHandler,
		profileHandler,
		locationHandler,
		routingHandler,
		dispatchHandler,
		authMiddleware,
	)
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
		log.Printf("brigade service address: %s", brigadeServiceAddr)
		log.Printf("profile service address: %s", profileServiceAddr)
		log.Printf("location service address: %s", locationServiceAddr)
		log.Printf("routing service address: %s", routingServiceAddr)

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
