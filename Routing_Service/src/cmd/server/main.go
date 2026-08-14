package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"routing/pkg"
	"routing/pkg/closer"
	appconfig "routing/pkg/config"
	"routing/src/core/handler"
	"routing/src/core/repository"
	"routing/src/core/service"
	"routing/src/infrastructure/valhalla"

	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func main() {
	if err := appconfig.Load(); err != nil {
		panic("configuration error: " + err.Error())
	}
	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	logger, err := pkg.NewLogger()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	dependencies := closer.New()
	db, err := pgxpool.New(ctx, requiredEnv("DATABASE_URL", logger))
	if err != nil {
		fatalWithCleanup(logger, dependencies, "connect postgres", err)
	}
	dependencies.Add("postgres", func() error {
		db.Close()
		return nil
	})
	if err = db.Ping(ctx); err != nil {
		fatalWithCleanup(logger, dependencies, "ping postgres", err)
	}

	engine, err := valhalla.New(valhalla.Config{
		BaseURL: requiredEnv("VALHALLA_URL", logger),
		Timeout: envDuration("VALHALLA_TIMEOUT", 10*time.Second),
	})
	if err != nil {
		fatalWithCleanup(logger, dependencies, "create Valhalla client", err)
	}

	routeRepo := repository.NewRouteRepo(db, db)
	routingService := service.New(routeRepo, engine, logger)
	routingHandler := handler.New(routingService)

	workerCtx, cancelWorkers := context.WithCancel(context.Background())
	var workerWG sync.WaitGroup
	startOutboxRelay(
		workerCtx,
		&workerWG,
		db,
		dependencies,
		logger,
	)
	startTicketConsumer(db, dependencies, logger)

	listener, err := net.Listen(
		"tcp",
		":"+env("GRPC_PORT", "50057"),
	)
	if err != nil {
		fatalWithCleanup(logger, dependencies, "listen grpc", err)
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			pkg.RequestIDUnaryServerInterceptor,
			pkg.AccessLogUnaryServerInterceptor(logger),
		),
	)
	routingv1.RegisterRoutingServiceServer(grpcServer, routingHandler)

	serverErr := make(chan error, 1)
	go func() {
		logger.Info(
			"routing gRPC started",
			zap.String("address", listener.Addr().String()),
		)
		if serveErr := grpcServer.Serve(listener); serveErr != nil {
			serverErr <- serveErr
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("graceful shutdown started")
	case err = <-serverErr:
		logger.Error("gRPC server failed", zap.Error(err))
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(
		context.Background(),
		envDuration("SHUTDOWN_TIMEOUT", 20*time.Second),
	)
	defer cancelShutdown()

	serverDone := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(serverDone)
	}()
	select {
	case <-serverDone:
		logger.Info("gRPC server stopped")
	case <-shutdownCtx.Done():
		logger.Warn("gRPC shutdown timed out")
		grpcServer.Stop()
	}

	cancelWorkers()
	workersDone := make(chan struct{})
	go func() {
		workerWG.Wait()
		close(workersDone)
	}()
	select {
	case <-workersDone:
		logger.Info("background workers stopped")
	case <-shutdownCtx.Done():
		logger.Warn("worker shutdown timed out")
	}

	if closeErr := dependencies.Close(shutdownCtx); closeErr != nil {
		logger.Error("close dependencies", zap.Error(closeErr))
	}
	logger.Info("routing service stopped")
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func requiredEnv(key string, logger *zap.Logger) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		logger.Fatal(
			"required environment variable is missing",
			zap.String("key", key),
		)
	}
	return value
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(os.Getenv(key))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func split(value string) []string {
	result := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func fatalWithCleanup(
	logger *zap.Logger,
	dependencies *closer.Closer,
	message string,
	err error,
) {
	logger.Error(message, zap.Error(err))
	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()
	if closeErr := dependencies.Close(ctx); closeErr != nil {
		logger.Error("startup cleanup failed", zap.Error(closeErr))
	}
	_ = logger.Sync()
	os.Exit(1)
}
