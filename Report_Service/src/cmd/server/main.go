package main

import (
	"context"
	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	filev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/file/v1"
	reportv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/report/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"log"
	"net"
	"os"
	"os/signal"
	"report/pkg"
	appconfig "report/pkg/config"
	"report/src/core/handler"
	"report/src/core/repository"
	"report/src/core/service"
	"report/src/infrastructure/analyticsclient"
	"report/src/infrastructure/fileclient"
	"report/src/infrastructure/generator"
	"report/src/infrastructure/outboxrelay"
	"report/src/infrastructure/reportworker"
	"strings"
	"syscall"
	"time"
)

func main() {
	if e := appconfig.Load(); e != nil {
		log.Fatal(e)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger, e := pkg.NewLogger()
	if e != nil {
		log.Fatal(e)
	}
	defer logger.Sync()
	db, e := pgxpool.New(ctx, must("DATABASE_URL"))
	if e != nil {
		logger.Fatal("database connection failed", zap.Error(e))
	}
	defer db.Close()
	if e = db.Ping(ctx); e != nil {
		logger.Fatal("database unavailable", zap.Error(e))
	}
	analyticsConn := dial(must("ANALYTICS_SERVICE_ADDR"), logger)
	defer analyticsConn.Close()
	fileConn := dial(must("FILE_SERVICE_ADDR"), logger)
	defer fileConn.Close()
	repo := repository.NewRepository(db)
	svc := service.NewService(repo, analyticsclient.New(analyticsv1.NewAnalyticsServiceClient(analyticsConn)), fileclient.New(filev1.NewFileServiceClient(fileConn), env("FILE_UPLOAD_INTERNAL_ENDPOINT", "http://minio:9000")), generator.New(), logger)
	worker := reportworker.New(svc, logger, duration("WORKER_INTERVAL", time.Second))
	go run(ctx, "report worker", worker.Run, logger)
	brokers := split(env("KAFKA_BROKERS", ""))
	if len(brokers) > 0 {
		relay := outboxrelay.New(db, brokers, env("KAFKA_REPORT_TOPIC", "reports.events.v1"), logger)
		defer relay.Close()
		go run(ctx, "outbox relay", relay.Run, logger)
	}
	lis, e := net.Listen("tcp", ":"+env("GRPC_PORT", "50064"))
	if e != nil {
		logger.Fatal("listen failed", zap.Error(e))
	}
	server := grpc.NewServer()
	reportv1.RegisterReportServiceServer(server, handler.New(svc))
	hs := health.NewServer()
	healthv1.RegisterHealthServer(server, hs)
	hs.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	go func() {
		logger.Info("report gRPC started", zap.String("address", lis.Addr().String()))
		if e := server.Serve(lis); e != nil && ctx.Err() == nil {
			logger.Error("gRPC stopped", zap.Error(e))
			stop()
		}
	}()
	<-ctx.Done()
	hs.Shutdown()
	server.GracefulStop()
}
func dial(addr string, l *zap.Logger) *grpc.ClientConn {
	c, e := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if e != nil {
		l.Fatal("gRPC connection failed", zap.String("address", addr), zap.Error(e))
	}
	return c
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
func must(k string) string {
	v := env(k, "")
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}
func split(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
func duration(k string, d time.Duration) time.Duration {
	v, e := time.ParseDuration(os.Getenv(k))
	if e != nil || v <= 0 {
		return d
	}
	return v
}
