package main

import (
	"context"
	"errors"
	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	filev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/file/v1"
	reportv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/report/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"report/pkg"
	appconfig "report/pkg/config"
	"report/pkg/telemetry"
	"report/src/core/handler"
	"report/src/core/repository"
	"report/src/core/service"
	"report/src/infrastructure/analyticsclient"
	"report/src/infrastructure/completionconsumer"
	"report/src/infrastructure/completionhttp"
	"report/src/infrastructure/fileclient"
	"report/src/infrastructure/generator"
	"report/src/infrastructure/outboxrelay"
	"report/src/infrastructure/reportworker"
	"strings"
	"syscall"
	"time"
)

func main() {
	telemetryProviders, err := telemetry.Init(context.Background(), "report-service")
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
	logger, e := pkg.NewLogger()
	if e != nil {
		log.Fatal(e)
	}
	defer logger.Sync()
	db, e := telemetry.NewPostgresPool(ctx, must("DATABASE_URL"))
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
	files := fileclient.New(filev1.NewFileServiceClient(fileConn), env("FILE_UPLOAD_INTERNAL_ENDPOINT", "http://minio:9000"))
	reportGenerator := generator.New()
	svc := service.NewService(repo, analyticsclient.New(analyticsv1.NewAnalyticsServiceClient(analyticsConn)), files, reportGenerator, logger)
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
	server := grpc.NewServer(telemetry.GRPCServerOption())
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
	completionProcessor := completionhttp.New(files, reportGenerator, must("REPORT_INTERNAL_TOKEN"), logger)
	if len(brokers) > 0 {
		consumer, consumerErr := completionconsumer.New(
			brokers,
			env("KAFKA_TICKET_TOPIC", "tickets.events.v1"),
			env("KAFKA_REPORT_TOPIC", "reports.events.v1"),
			env("COMPLETION_CONSUMER_GROUP_ID", "report-completion-v1"),
			completionProcessor,
			logger,
		)
		if consumerErr != nil {
			logger.Fatal("completion consumer initialization failed", zap.Error(consumerErr))
		}
		defer consumer.Close()
		go run(ctx, "completion consumer", consumer.Run, logger)
	}
	internalServer := completionhttp.HTTPServer(
		":"+env("INTERNAL_HTTP_PORT", "8084"),
		telemetry.HTTPHandler(completionProcessor.Handler(), "report.internal.http"),
	)
	go func() {
		logger.Info("report internal HTTP started", zap.String("address", internalServer.Addr))
		if err := internalServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
			logger.Error("report internal HTTP stopped", zap.Error(err))
			stop()
		}
	}()
	<-ctx.Done()
	hs.Shutdown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = internalServer.Shutdown(shutdownCtx)
	server.GracefulStop()
}
func dial(addr string, l *zap.Logger) *grpc.ClientConn {
	c, e := grpc.NewClient(
		addr,
		telemetry.GRPCClientOption(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
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
