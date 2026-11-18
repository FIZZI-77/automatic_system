package main

import (
	"analytics/pkg"
	appconfig "analytics/pkg/config"
	"analytics/pkg/telemetry"
	"analytics/src/core/handler"
	"analytics/src/core/repository"
	"analytics/src/core/service"
	"analytics/src/infrastructure/eventconsumer"
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	telemetryProviders, err := telemetry.Init(context.Background(), "analytics-service")

	if err != nil {
		log.Fatalf("initialize OpenTelemetry: %v", err)
	}

	defer func() {

		if shutdownErr := telemetryProviders.Close(); shutdownErr != nil {
			log.Printf("shutdown OpenTelemetry: %v", shutdownErr)
		}

	}()

	if e := appconfig.Load(); e != nil {
		log.Fatalf("configuration error: %v", e)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger, e := pkg.NewLogger()

	if e != nil {
		log.Fatal(e)
	}

	defer func(logger *zap.Logger) {
		err := logger.Sync()
		if err != nil {

		}
	}(logger)

	db, e := clickhouse.Open(&clickhouse.Options{
		Addr: split(required("CLICKHOUSE_ADDR")),
		Auth: clickhouse.Auth{
			Database: env("CLICKHOUSE_DATABASE", "analytics"),
			Username: env("CLICKHOUSE_USER", "default"),
			Password: os.Getenv("CLICKHOUSE_PASSWORD"),
		},
		Settings: clickhouse.Settings{
			"max_threads": 1,
		},
		MaxOpenConns: 4,
	})

	if e != nil {
		logger.Fatal("clickhouse failed", zap.Error(e))
	}

	defer func(db driver.Conn) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	if e = db.Ping(ctx); e != nil {
		logger.Fatal("clickhouse unavailable", zap.Error(e))
	}

	repo := repository.NewRepository(db)
	svc := service.NewService(repo, logger)
	var workers []*eventconsumer.Worker

	for _, topic := range split(required("KAFKA_TOPICS")) {
		w := eventconsumer.New(split(required("KAFKA_BROKERS")), topic, env("KAFKA_GROUP", "analytics-service"), svc, logger)
		workers = append(workers, w)
		go run(ctx, "consumer "+topic, w.Run, logger)
	}

	defer func() {
		for _, w := range workers {
			_ = w.Close()
		}
	}()

	lis, e := net.Listen("tcp", ":"+env("GRPC_PORT", "50063"))

	if e != nil {
		logger.Fatal("listen failed", zap.Error(e))
	}

	server := grpc.NewServer(telemetry.GRPCServerOption())

	analyticsv1.RegisterAnalyticsServiceServer(server, handler.New(svc))

	hs := health.NewServer()

	healthv1.RegisterHealthServer(server, hs)

	hs.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)

	go func() {
		logger.Info("analytics gRPC started", zap.String("address", lis.Addr().String()))

		if e := server.Serve(lis); e != nil && ctx.Err() == nil {
			logger.Error("gRPC stopped", zap.Error(e))
			stop()
		}

	}()

	<-ctx.Done()

	hs.Shutdown()

	server.GracefulStop()
}
func run(c context.Context, n string, f func(context.Context) error, l *zap.Logger) {

	if e := f(c); e != nil && c.Err() == nil {
		l.Error(n+" stopped", zap.Error(e))
	}

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
		log.Fatalf("%s is required", k)
	}

	return v
}
func split(v string) []string {
	var out []string
	for x := range strings.SplitSeq(v, ",") {

		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}

	}
	return out
}
