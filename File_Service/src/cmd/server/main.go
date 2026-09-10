package main

import (
	"context"
	"errors"
	"file/pkg/telemetry"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"file/pkg"
	appconfig "file/pkg/config"
	"file/src/core/handler"
	"file/src/core/repository"
	"file/src/core/service"
	"file/src/infrastructure/storage"
	filev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/file/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	telemetryProviders, err := telemetry.Init(context.Background(), "file-service")
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
	logger, err := pkg.NewLogger()
	if err != nil {
		log.Fatal(err)
	}
	defer logger.Sync()

	ctx := context.Background()
	writeDB, err := telemetry.NewPostgresPool(ctx, required("DATABASE_URL"))
	if err != nil {
		logger.Fatal("failed to connect to postgres", zap.Error(err))
	}
	defer writeDB.Close()

	readDB, err := telemetry.NewPostgresPool(ctx, env("READ_DATABASE_URL", required("DATABASE_URL")))
	if err != nil {
		logger.Fatal("failed to connect to postgres replica", zap.Error(err))
	}
	defer readDB.Close()
	store := storage.New(storage.Config{
		Endpoint:       required("S3_ENDPOINT"),
		PublicEndpoint: env("S3_PUBLIC_ENDPOINT", required("S3_ENDPOINT")),
		Region:         env("S3_REGION", "us-east-1"),
		AccessKey:      required("S3_ACCESS_KEY"),
		SecretKey:      required("S3_SECRET_KEY"),
		Bucket:         env("S3_BUCKET", "city-files"),
		UsePathStyle:   env("S3_PATH_STYLE", "true") == "true",
	})
	if err = store.EnsureBucket(ctx); err != nil {
		logger.Fatal("failed to ensure S3 bucket", zap.Error(err))
	}
	ttl, _ := time.ParseDuration(env("PRESIGN_TTL", "15m"))
	api := service.New(repository.New(writeDB, readDB), store, ttl, logger)
	grpcServer := grpc.NewServer(
		telemetry.GRPCServerOption(),
		grpc.ChainUnaryInterceptor(
			pkg.RequestIDUnaryServerInterceptor,
			pkg.AccessLogUnaryServerInterceptor(logger),
		),
	)
	filev1.RegisterFileServiceServer(grpcServer, handler.New(api, logger))
	healthv1.RegisterHealthServer(grpcServer, health.NewServer())

	listener, err := net.Listen("tcp", ":"+env("GRPC_PORT", "50059"))
	if err != nil {
		logger.Fatal("failed to listen gRPC", zap.Error(err))
	}
	go func() {
		logger.Info("file gRPC server started", zap.String("address", listener.Addr().String()))
		if serveErr := grpcServer.Serve(listener); serveErr != nil {
			logger.Fatal("gRPC server stopped", zap.Error(serveErr))
		}
	}()

	select {}
}
func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
func required(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		log.Fatal(errors.New(k + " is required"))
	}
	return v
}
