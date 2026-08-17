package main

import (
	"context"
	"errors"
	"gateway/pkg/closer"
	appconfig "gateway/pkg/config"
	"gateway/src/core/handlers"
	"gateway/src/core/idempotency"
	"gateway/src/core/middleware"
	"gateway/src/core/requestid"
	"gateway/src/core/retry"
	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	assetv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/asset/v1"
	auditv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/audit/v1"
	authv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/auth/v1"
	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	dispatchv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/dispatch/v1"
	filev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/file/v1"
	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	notificationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/notification/v1"
	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	reportv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/report/v1"
	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	slav1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/sla/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	if err := appconfig.Load(); err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	dependencies := closer.New()
	redisClient := redis.NewClient(&redis.Options{
		Addr:     getEnv("REDIS_ADDR", "localhost:6379"),
		Password: getEnv("REDIS_PASSWORD", ""),
		DB:       getEnvInt("REDIS_DB", 0),
	})
	redisCtx, redisCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := redisClient.Ping(redisCtx).Err(); err != nil {
		redisCancel()
		log.Fatalf("failed to connect to rate limiter Redis: %v", err)
	}
	redisCancel()
	dependencies.Add("rate limiter redis", redisClient.Close)
	rateLimiter := middleware.NewRedisRateLimiter(redisClient, getEnv("RATE_LIMIT_PREFIX", "gateway:ratelimit"))

	authServiceAddr := getEnv("AUTH_SERVICE_ADDR", "localhost:50051")
	ticketServiceAddr := getEnv("TICKET_SERVICE_ADDR", "localhost:50052")
	departmentServiceAddr := getEnv("DEPARTMENT_SERVICE_ADDR", "localhost:50053")
	brigadeServiceAddr := getEnv("BRIGADE_SERVICE_ADDR", "localhost:50054")
	profileServiceAddr := getEnv("PROFILE_SERVICE_ADDR", "localhost:50055")
	locationServiceAddr := getEnv("LOCATION_SERVICE_ADDR", "localhost:50056")
	routingServiceAddr := getEnv("ROUTING_SERVICE_ADDR", "localhost:50057")
	dispatchServiceAddr := getEnv("DISPATCH_SERVICE_ADDR", "localhost:50058")
	fileServiceAddr := getEnv("FILE_SERVICE_ADDR", "localhost:50059")
	slaServiceAddr := getEnv("SLA_SERVICE_ADDR", "localhost:50060")
	notificationServiceAddr := getEnv("NOTIFICATION_SERVICE_ADDR", "localhost:50061")
	auditServiceAddr := getEnv("AUDIT_SERVICE_ADDR", "localhost:50062")
	analyticsServiceAddr := getEnv("ANALYTICS_SERVICE_ADDR", "localhost:50063")
	reportServiceAddr := getEnv("REPORT_SERVICE_ADDR", "localhost:50064")
	assetServiceAddr := getEnv("ASSET_SERVICE_ADDR", "localhost:50065")
	gatewayAddr := getEnv("GATEWAY_ADDR", ":8080")
	publicKeyPath := getEnv("JWT_PUBLIC_KEY_PATH", "./keys/public.pem")

	authConn, err := grpc.NewClient(
		grpcTarget(authServiceAddr),
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
	waitForGRPCReady("auth", authConn)
	defer closeDependencies(dependencies)

	authClient := authv1.NewAuthServiceClient(authConn)

	ticketConn, err := grpc.NewClient(
		grpcTarget(ticketServiceAddr),
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
	waitForGRPCReady("ticket", ticketConn)

	ticketClient := ticketv1.NewTicketServiceClient(ticketConn)

	departmentConn, err := grpc.NewClient(
		grpcTarget(departmentServiceAddr),
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
	waitForGRPCReady("department", departmentConn)

	departmentClient := departmentv1.NewDepartmentServiceClient(departmentConn)

	brigadeConn, err := grpc.NewClient(
		grpcTarget(brigadeServiceAddr),
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
	waitForGRPCReady("brigade", brigadeConn)

	brigadeClient := brigadev1.NewBrigadeServiceClient(brigadeConn)

	profileConn, err := grpc.NewClient(
		grpcTarget(profileServiceAddr),
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
	waitForGRPCReady("profile", profileConn)

	profileClient := profilev1.NewProfileServiceClient(profileConn)

	locationConn, err := grpc.NewClient(
		grpcTarget(locationServiceAddr),
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
	waitForGRPCReady("location", locationConn)

	locationClient := locationv1.NewLocationServiceClient(locationConn)

	routingConn, err := grpc.NewClient(
		grpcTarget(routingServiceAddr),
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
	waitForGRPCReady("routing", routingConn)

	routingClient := routingv1.NewRoutingServiceClient(routingConn)
	dispatchConn, err := grpc.NewClient(
		grpcTarget(dispatchServiceAddr),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(requestid.UnaryClientInterceptor, idempotency.UnaryClientInterceptor, retry.UnaryClientInterceptor),
	)
	if err != nil {
		log.Fatalf("failed to connect to dispatch service: %v", err)
	}
	dependencies.Add("dispatch grpc connection", dispatchConn.Close)
	waitForGRPCReady("dispatch", dispatchConn)
	dispatchClient := dispatchv1.NewDispatchServiceClient(dispatchConn)
	fileConn, err := grpc.NewClient(grpcTarget(fileServiceAddr), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithChainUnaryInterceptor(requestid.UnaryClientInterceptor, idempotency.UnaryClientInterceptor, retry.UnaryClientInterceptor))
	if err != nil {
		log.Fatalf("failed to connect to file service: %v", err)
	}
	dependencies.Add("file grpc connection", fileConn.Close)
	waitForGRPCReady("file", fileConn)
	fileClient := filev1.NewFileServiceClient(fileConn)
	slaConn, err := grpc.NewClient(grpcTarget(slaServiceAddr), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithChainUnaryInterceptor(requestid.UnaryClientInterceptor, idempotency.UnaryClientInterceptor, retry.UnaryClientInterceptor))
	if err != nil {
		log.Fatalf("failed to connect to SLA service: %v", err)
	}
	dependencies.Add("sla grpc connection", slaConn.Close)
	waitForGRPCReady("sla", slaConn)
	slaClient := slav1.NewSLAServiceClient(slaConn)
	notificationConn, err := grpc.NewClient(grpcTarget(notificationServiceAddr), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithChainUnaryInterceptor(requestid.UnaryClientInterceptor, idempotency.UnaryClientInterceptor, retry.UnaryClientInterceptor))
	if err != nil {
		log.Fatalf("failed to connect to notification service: %v", err)
	}
	dependencies.Add("notification grpc connection", notificationConn.Close)
	waitForGRPCReady("notification", notificationConn)
	notificationClient := notificationv1.NewNotificationServiceClient(notificationConn)
	auditConn, err := grpc.NewClient(grpcTarget(auditServiceAddr), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithChainUnaryInterceptor(requestid.UnaryClientInterceptor, idempotency.UnaryClientInterceptor, retry.UnaryClientInterceptor))
	if err != nil {
		log.Fatalf("failed to connect to audit service: %v", err)
	}
	dependencies.Add("audit grpc connection", auditConn.Close)
	waitForGRPCReady("audit", auditConn)
	auditClient := auditv1.NewAuditServiceClient(auditConn)
	analyticsConn, err := grpc.NewClient(grpcTarget(analyticsServiceAddr), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithChainUnaryInterceptor(requestid.UnaryClientInterceptor, idempotency.UnaryClientInterceptor, retry.UnaryClientInterceptor))
	if err != nil {
		log.Fatalf("failed to connect to analytics service: %v", err)
	}
	dependencies.Add("analytics grpc connection", analyticsConn.Close)
	waitForGRPCReady("analytics", analyticsConn)
	analyticsClient := analyticsv1.NewAnalyticsServiceClient(analyticsConn)
	reportConn, err := grpc.NewClient(grpcTarget(reportServiceAddr), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithChainUnaryInterceptor(requestid.UnaryClientInterceptor, idempotency.UnaryClientInterceptor, retry.UnaryClientInterceptor))
	if err != nil {
		log.Fatalf("failed to connect to report service: %v", err)
	}
	dependencies.Add("report grpc connection", reportConn.Close)
	waitForGRPCReady("report", reportConn)
	reportClient := reportv1.NewReportServiceClient(reportConn)
	assetConn, err := grpc.NewClient(grpcTarget(assetServiceAddr), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithChainUnaryInterceptor(requestid.UnaryClientInterceptor, idempotency.UnaryClientInterceptor, retry.UnaryClientInterceptor))
	if err != nil {
		log.Fatal(err)
	}
	dependencies.Add("asset grpc connection", assetConn.Close)
	waitForGRPCReady("asset", assetConn)
	assetClient := assetv1.NewAssetServiceClient(assetConn)

	authMiddleware, err := middleware.NewAuthMiddleware(
		publicKeyPath,
		"auth-jwt",
		"api-gateway",
	)
	if err != nil {
		log.Fatalf("failed to init auth middleware: %v", err)
	}

	authHandler := handlers.NewAuthHandler(authClient)
	ticketHandler := handlers.NewTicketHandler(ticketClient, brigadeClient)
	departmentHandler := handlers.NewDepartmentHandler(departmentClient)
	brigadeHandler := handlers.NewBrigadeHandler(brigadeClient)
	profileHandler := handlers.NewProfileHandler(profileClient)
	locationHandler := handlers.NewLocationHandler(locationClient)
	routingHandler := handlers.NewRoutingHandler(routingClient)
	dispatchHandler := handlers.NewDispatchHandler(dispatchClient)
	fileHandler := handlers.NewFileHandler(fileClient)
	slaHandler := handlers.NewSLAHandler(slaClient)
	notificationHandler := handlers.NewNotificationHandler(notificationClient, redisClient, getEnv("NOTIFICATION_LIVE_PREFIX", "notifications:user:"))
	auditHandler := handlers.NewAuditHandler(auditClient)
	analyticsHandler := handlers.NewAnalyticsHandler(analyticsClient)
	reportHandler := handlers.NewReportHandler(reportClient, ticketClient, brigadeClient, profileClient, getEnv("REPORT_INTERNAL_URL", "http://report-service:8084"), getEnv("REPORT_INTERNAL_TOKEN", ""))
	assetHandler := handlers.NewAssetHandler(assetClient)
	handler := handlers.NewHandler(
		authHandler,
		ticketHandler,
		departmentHandler,
		brigadeHandler,
		profileHandler,
		locationHandler,
		routingHandler,
		dispatchHandler,
		fileHandler,
		slaHandler,
		notificationHandler,
		auditHandler,
		analyticsHandler,
		reportHandler,
		assetHandler,
		authMiddleware,
		rateLimiter,
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

func waitForGRPCReady(name string, conn *grpc.ClientConn) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn.Connect()
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return
		}
		if !conn.WaitForStateChange(ctx, state) {
			log.Fatalf("%s gRPC service is not ready: %v", name, ctx.Err())
		}
	}
}

func grpcTarget(address string) string { return "passthrough:///" + address }

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

func getEnvInt(key string, defaultValue int) int {
	value := getEnv(key, "")
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		log.Fatalf("invalid %s: %v", key, err)
	}
	return parsed
}
