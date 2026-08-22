package main

import (
	"context"
	notificationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/notification/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"log"
	"net"
	"notification/pkg"
	appconfig "notification/pkg/config"
	"notification/src/core/handler"
	"notification/src/core/repository"
	"notification/src/core/service"
	"notification/src/infrastructure/delivery"
	"notification/src/infrastructure/eventconsumer"
	"notification/src/infrastructure/live"
	"notification/src/infrastructure/sender"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
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
	db, e := pgxpool.New(ctx, must("DATABASE_URL"))
	if e != nil {
		logger.Fatal("database failed", zap.Error(e))
	}
	defer db.Close()
	if e = db.Ping(ctx); e != nil {
		logger.Fatal("database unavailable", zap.Error(e))
	}
	redisClient := redis.NewClient(&redis.Options{Addr: env("REDIS_ADDR", "redis-notification:6379"), Password: os.Getenv("REDIS_PASSWORD")})
	defer redisClient.Close()
	if e = redisClient.Ping(ctx).Err(); e != nil {
		logger.Fatal("redis unavailable", zap.Error(e))
	}
	repo := repository.New(db)
	svc := service.New(repo, live.New(redisClient, env("LIVE_CHANNEL_PREFIX", "notifications:user:")))
	senders := map[string]sender.Sender{"IN_APP": sender.InApp{}, "EMAIL": sender.NewEmail(env("SMTP_ADDR", "mailhog:1025"), env("SMTP_FROM", "no-reply@automatic-system.local")), "SMS": sender.Disabled{Channel: "SMS"}}
	if path := strings.TrimSpace(os.Getenv("FCM_SERVICE_ACCOUNT_FILE")); path != "" {
		fcm, err := sender.NewFCM(ctx, path)
		if err != nil {
			logger.Fatal("FCM initialization failed", zap.Error(err))
		}
		senders["PUSH"] = fcm
	} else {
		senders["PUSH"] = sender.Disabled{Channel: "FCM"}
		logger.Warn("FCM disabled: service account is not configured")
	}
	worker := delivery.New(repo, senders, logger)
	go run(ctx, "delivery worker", worker.Run, logger)
	brokers := split(os.Getenv("KAFKA_BROKERS"))
	var consumers []*eventconsumer.Worker
	for _, topic := range split(env("KAFKA_TOPICS", "tickets.events.v1,sla.events.v1,dispatch.events.v1,departments.events.v1,brigades.events.v1,locations.events.v1,routing.events.v1,files.events.v1")) {
		w := eventconsumer.New(brokers, topic, env("KAFKA_GROUP", "notification-service"), svc, logger)
		consumers = append(consumers, w)
		go run(ctx, "consumer "+topic, w.Run, logger)
	}
	defer func() {
		for _, w := range consumers {
			_ = w.Close()
		}
	}()
	lis, e := net.Listen("tcp", ":"+env("GRPC_PORT", "50061"))
	if e != nil {
		logger.Fatal("listen failed", zap.Error(e))
	}
	server := grpc.NewServer()
	notificationv1.RegisterNotificationServiceServer(server, handler.New(svc))
	hs := health.NewServer()
	healthv1.RegisterHealthServer(server, hs)
	hs.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	go func() {
		logger.Info("notification gRPC started", zap.String("address", lis.Addr().String()))
		if e := server.Serve(lis); e != nil {
			stop()
		}
	}()
	<-ctx.Done()
	hs.Shutdown()
	server.GracefulStop()
}
func run(c context.Context, name string, f func(context.Context) error, l *zap.Logger) {
	if e := f(c); e != nil && c.Err() == nil {
		l.Error(name+" stopped", zap.Error(e))
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
		log.Fatalf("%s required", k)
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
