package main

import (
	"context"
	"errors"
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
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func main() {
	if err := appconfig.Load(); err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	logger, err := pkg.NewLogger()
	if err != nil {
		log.Fatal(err)
	}
	defer logger.Sync()

	ctx := context.Background()
	db, err := pgxpool.New(ctx, required("DATABASE_URL"))
	if err != nil {
		logger.Fatal("failed to connect to postgres", zap.Error(err))
	}
	defer db.Close()
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
	api := service.New(repository.New(db), store, ttl, logger)
	grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor(
		pkg.RequestIDUnaryServerInterceptor,
		pkg.AccessLogUnaryServerInterceptor(logger),
	))
	filev1.RegisterFileServiceServer(grpcServer, handler.New(api, logger))

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
