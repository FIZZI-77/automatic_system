package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"asset/pkg"
	appconfig "asset/pkg/config"
	"asset/pkg/telemetry"
	"asset/src/core/handler"
	"asset/src/core/repository"
	"asset/src/core/service"
	"asset/src/infrastructure/criticalticket"
	"asset/src/infrastructure/outboxrelay"
	"asset/src/infrastructure/tickethistory"

	assetv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/asset/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
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

	defer func() { _ = l.Sync() }() // Best effort flush during shutdown.
	db, e := telemetry.NewPostgresPool(ctx, must("DATABASE_URL"))

	if e != nil {
		l.Fatal("database failed", zap.Error(e))
	}

	defer db.Close()

	if e = db.Ping(ctx); e != nil {
		l.Fatal("database unavailable", zap.Error(e))
	}

	assetRepo := repository.NewAssetRepoStruct(db)
	s := service.NewService(&repository.Repository{AssetRepository: assetRepo}, l)
	brokers := split(env("KAFKA_BROKERS", ""))

	if len(brokers) > 0 {
		w := outboxrelay.New(db, brokers, env("KAFKA_ASSET_TOPIC", "assets.events.v1"), l)
		defer func() { _ = w.Close() }() // Best effort cleanup after the operation.
		go func() {
			if err := w.Run(ctx); err != nil && ctx.Err() == nil {
				l.Error("asset outbox relay stopped", zap.Error(err))
			}
		}()
		startCriticalTicketWorker(ctx, brokers, l)

		reader := kafka.NewReader(kafka.ReaderConfig{
			Brokers: brokers, Topic: env("KAFKA_TICKET_TOPIC", "tickets.events.v1"),
			GroupID: "asset-ticket-history-v1", StartOffset: kafka.FirstOffset,
		})
		done := make(chan struct{})
		go func() {
			defer close(done)
			tickethistory.Run(ctx, reader, assetRepo, l)
		}()
		defer func() {
			stop()
			_ = reader.Close()
			<-done
		}()
	}

	history := &http.Server{
		Addr: ":" + env("ASSET_HISTORY_PORT", "8085"), Handler: handler.AssetHistoryRoutes(assetRepo),
		ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 8 * time.Second,
	}
	go func() {
		if err := history.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.Error("asset history server stopped", zap.Error(err))
			stop()
		}
	}()

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
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := history.Shutdown(shutdownCtx); err != nil {
		l.Warn("shutdown asset history server", zap.Error(err))
	}
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

func startCriticalTicketWorker(ctx context.Context, brokers []string, logger *zap.Logger) {
	categoryID := env("CRITICAL_RISK_TICKET_CATEGORY_ID", "")
	requesterID := env("CRITICAL_RISK_TICKET_REQUESTER_ID", "")

	if categoryID == "" || requesterID == "" {
		logger.Info("critical risk ticket worker disabled")
		return
	}

	conn, err := grpc.NewClient(env("TICKET_SERVICE_ADDR", "ticket-service:50052"), grpc.WithTransportCredentials(insecure.NewCredentials()), telemetry.GRPCClientOption())

	if err != nil {
		logger.Error("critical risk ticket worker disabled", zap.Error(err))
		return
	}

	worker, err := criticalticket.New(criticalticket.Config{
		Brokers:     brokers,
		Topic:       env("KAFKA_ASSET_TOPIC", "assets.events.v1"),
		GroupID:     env("CRITICAL_RISK_TICKET_GROUP_ID", "asset-critical-ticket-v1"),
		CategoryID:  categoryID,
		RequesterID: requesterID,
		ActorRoles:  env("CRITICAL_RISK_TICKET_ACTOR_ROLES", "dispatcher"),
	}, ticketv1.NewTicketServiceClient(conn), logger)

	if err != nil {
		logger.Error("critical risk ticket worker disabled", zap.Error(err))
		_ = conn.Close()
		return
	}

	go func() {
		<-ctx.Done()
		_ = worker.Close()
		_ = conn.Close()
	}()
	go func() {

		if err := worker.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("critical risk ticket worker stopped", zap.Error(err))
		}

	}()
}
