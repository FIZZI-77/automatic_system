package main

import (
	"asset/pkg"
	appconfig "asset/pkg/config"
	"asset/pkg/telemetry"
	"asset/src/core/handler"
	"asset/src/core/repository"
	"asset/src/core/service"
	"asset/src/infrastructure/outboxrelay"
	"context"
	assetv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/asset/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	telemetryProviders, err := telemetry.Init(context.Background(), "asset-service")
	if err != nil {
		log.Fatalf("initialize OpenTelemetry: %v", err)
	}
	defer func() {
		if shutdownErr := telemetryProviders.Close(); shutdownErr != nil {
			log.Printf("shutdown OpenTelemetry: %v", shutdownErr)
		}
	}()

	if e := appconfig.Load(); e != nil {
		log.Fatal(e)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	l, e := pkg.NewLogger()
	if e != nil {
		log.Fatal(e)
	}
	defer l.Sync()
	db, e := telemetry.NewPostgresPool(ctx, must("DATABASE_URL"))
	if e != nil {
		l.Fatal("database failed", zap.Error(e))
	}
	defer db.Close()
	if e = db.Ping(ctx); e != nil {
		l.Fatal("database unavailable", zap.Error(e))
	}
	s := service.NewService(repository.NewRepository(db), l)
	brokers := split(env("KAFKA_BROKERS", ""))
	if len(brokers) > 0 {
		w := outboxrelay.New(db, brokers, env("KAFKA_ASSET_TOPIC", "assets.events.v1"), l)
		defer w.Close()
		go w.Run(ctx)
	}
	lis, e := net.Listen("tcp", ":"+env("GRPC_PORT", "50065"))
	if e != nil {
		l.Fatal("listen failed", zap.Error(e))
	}
	g := grpc.NewServer(telemetry.GRPCServerOption())
	assetv1.RegisterAssetServiceServer(g, handler.New(s))
	hs := health.NewServer()
	healthv1.RegisterHealthServer(g, hs)
	hs.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	go func() {
		l.Info("asset gRPC started", zap.String("address", lis.Addr().String()))
		if e := g.Serve(lis); e != nil && ctx.Err() == nil {
			l.Error("gRPC stopped", zap.Error(e))
			stop()
		}
	}()
	<-ctx.Done()
	hs.Shutdown()
	g.GracefulStop()
}
func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
func must(k string) string {
	v := env(k, "")
	if v == "" {
		log.Fatalf("%s required", k)
	}
	return v
}
func split(v string) []string {
	var o []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			o = append(o, x)
		}
	}
	return o
}
