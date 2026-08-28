package main

import (
	"context"
	slav1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/sla/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"log"
	"net"
	"os"
	"os/signal"
	"sla/pkg"
	appconfig "sla/pkg/config"
	"sla/pkg/telemetry"
	"sla/src/core/handler"
	"sla/src/core/repository"
	"sla/src/core/service"
	"sla/src/infrastructure/outboxrelay"
	"sla/src/infrastructure/ticketconsumer"
	"strings"
	"syscall"
	"time"
)

func main() {
	telemetryProviders, err := telemetry.Init(context.Background(), "sla-service")
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
	s := service.New(repository.New(db))
	brokers := split(os.Getenv("KAFKA_BROKERS"))
	if len(brokers) > 0 {
		consumer := ticketconsumer.New(brokers, env("KAFKA_TICKET_TOPIC", "tickets.events.v1"), env("KAFKA_CONSUMER_GROUP", "sla-service"), s, logger)
		relay := outboxrelay.New(db, brokers, env("KAFKA_SLA_TOPIC", "sla.events.v1"), logger)
		defer consumer.Close()
		defer relay.Close()
		go run(ctx, "ticket consumer", consumer.Run, logger)
		go run(ctx, "outbox relay", relay.Run, logger)
	}
	go deadlines(ctx, s, duration("DEADLINE_SCAN_INTERVAL", time.Second), logger)
	lis, e := net.Listen("tcp", ":"+env("GRPC_PORT", "50060"))
	if e != nil {
		logger.Fatal("listen failed", zap.Error(e))
	}
	server := grpc.NewServer(telemetry.GRPCServerOption())
	slav1.RegisterSLAServiceServer(server, handler.New(s))
	hs := health.NewServer()
	healthv1.RegisterHealthServer(server, hs)
	hs.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	go func() {
		logger.Info("SLA gRPC started", zap.String("address", lis.Addr().String()))
		if e := server.Serve(lis); e != nil {
			stop()
		}
	}()
	<-ctx.Done()
	hs.Shutdown()
	server.GracefulStop()
}
func run(ctx context.Context, name string, f func(context.Context) error, l *zap.Logger) {
	if e := f(ctx); e != nil && ctx.Err() == nil {
		l.Error(name+" stopped", zap.Error(e))
	}
}
func deadlines(ctx context.Context, s *service.Service, d time.Duration, l *zap.Logger) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if e := s.CheckDeadlines(ctx, now.UTC()); e != nil {
				l.Error("deadline scan failed", zap.Error(e))
			}
		}
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
