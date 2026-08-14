package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"location/pkg"
	"location/pkg/closer"
	appconfig "location/pkg/config"
	"location/src/core/handler"
	"location/src/core/httptransport"
	"location/src/core/repository"
	"location/src/core/service"
	"location/src/infrastructure/positionhistory"
	"location/src/infrastructure/signalmonitor"
	"location/src/infrastructure/streamrelay"

	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func main() {
	if err := appconfig.Load(); err != nil {
		panic("configuration error: " + err.Error())
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log, err := pkg.NewLogger()
	if err != nil {
		panic(err)
	}
	defer log.Sync()
	dependencies := closer.New()
	db, err := pgxpool.New(ctx, requiredEnv("DATABASE_URL", log))
	if err != nil {
		fatalWithCleanup(log, dependencies, "connect postgres", err)
	}
	dependencies.Add("postgres", func() error { db.Close(); return nil })
	if err = db.Ping(ctx); err != nil {
		fatalWithCleanup(log, dependencies, "ping postgres", err)
	}
	rdb := newRedisClient()
	dependencies.Add("redis", rdb.Close)
	if err = rdb.Ping(ctx).Err(); err != nil {
		fatalWithCleanup(log, dependencies, "ping redis", err)
	}
	signalStaleAfter := envDuration("SIGNAL_STALE_AFTER", 15*time.Second)
	signalOfflineAfter := envDuration("SIGNAL_OFFLINE_AFTER", 60*time.Second)
	repo := repository.NewRepositoryFromClientsWithConfig(
		repository.DBPools{Write: db, Read: db},
		rdb,
		repository.CurrentLocationRepoConfig{
			StaleAfter:   signalStaleAfter,
			OfflineAfter: signalOfflineAfter,
		},
	)
	buffer := service.NewMemoryPositionBuffer(envInt("HISTORY_BUFFER_CAPACITY", 10000))
	historyWorker, err := positionhistory.New(
		buffer,
		repo,
		positionhistory.Config{
			BatchSize:       envInt("HISTORY_BATCH_SIZE", 500),
			FlushInterval:   envDuration("HISTORY_FLUSH_INTERVAL", 5*time.Second),
			ShutdownTimeout: 5 * time.Second,
		},
		log,
	)
	if err != nil {
		fatalWithCleanup(log, dependencies, "create history worker", err)
	}
	locationService := service.NewServiceWithLogger(repo, historyWorker, log)
	workerCtx, cancelWorkers := context.WithCancel(context.Background())
	var workerWG sync.WaitGroup
	startWorker := func(name string, run func()) {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			log.Info("worker started", zap.String("worker", name))
			run()
			log.Info("worker stopped", zap.String("worker", name))
		}()
	}
	startWorker("position history", func() {
		if runErr := historyWorker.Run(workerCtx); runErr != nil {
			log.Error("position history worker failed", zap.Error(runErr))
			stop()
		}
	})
	signalWorker := signalmonitor.New(
		locationService,
		signalmonitor.Config{
			Interval:     envDuration("SIGNAL_SCAN_INTERVAL", 5*time.Second),
			StaleAfter:   signalStaleAfter,
			OfflineAfter: signalOfflineAfter,
			BatchSize:    int32(envInt("SIGNAL_BATCH_SIZE", 500)),
		},
		log,
	)
	startWorker("signal monitor", func() { signalWorker.Run(workerCtx) })
	if brokers := split(os.Getenv("KAFKA_BROKERS")); len(brokers) > 0 {
		relay := streamrelay.New(
			rdb,
			streamrelay.Config{
				Brokers:  brokers,
				Topic:    env("KAFKA_LOCATION_TOPIC", "locations.events.v1"),
				Stream:   env("REDIS_EVENTS_STREAM", "locations:events"),
				Group:    env("REDIS_EVENTS_GROUP", "location-kafka-relay"),
				Consumer: env("REDIS_EVENTS_CONSUMER", "location-service"),
			},
			log,
		)
		dependencies.Add("stream relay", relay.Close)
		startWorker("stream relay", func() { relay.Run(workerCtx) })
	}
	grpcListener, err := net.Listen("tcp", ":"+env("GRPC_PORT", "50056"))
	if err != nil {
		fatalWithCleanup(log, dependencies, "listen grpc", err)
	}
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			pkg.RequestIDUnaryServerInterceptor,
			pkg.AccessLogUnaryServerInterceptor(log),
		),
	)
	locationv1.RegisterLocationServiceServer(grpcServer, handler.New(locationService))
	go func() {
		log.Info("grpc started", zap.String("address", grpcListener.Addr().String()))
		if serveErr := grpcServer.Serve(grpcListener); serveErr != nil {
			log.Error("grpc stopped", zap.Error(serveErr))
			stop()
		}
	}()
	httpServer := &http.Server{
		Addr: ":" + env("HTTP_PORT", "8080"),
		Handler: pkg.HTTPMiddleware(
			log,
			httptransport.New(locationService, os.Getenv("TRANSPONDER_API_KEY")).Routes(),
		),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Info("http started", zap.String("address", httpServer.Addr))
		if serveErr := httpServer.ListenAndServe(); serveErr != nil &&
			!errors.Is(serveErr, http.ErrServerClosed) {
			log.Error("http stopped", zap.Error(serveErr))
			stop()
		}
	}()
	<-ctx.Done()
	log.Info("graceful shutdown started")
	shutdownCtx, cancelShutdown := context.WithTimeout(
		context.Background(),
		envDuration("SHUTDOWN_TIMEOUT", 20*time.Second),
	)
	defer cancelShutdown()
	serversDone := make(chan struct{})
	go func() {
		var serverWG sync.WaitGroup
		serverWG.Add(2)
		go func() {
			defer serverWG.Done()
			if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
				log.Warn("HTTP graceful shutdown failed", zap.Error(shutdownErr))
			}
		}()
		go func() { defer serverWG.Done(); grpcServer.GracefulStop() }()
		serverWG.Wait()
		close(serversDone)
	}()
	select {
	case <-serversDone:
		log.Info("request servers stopped")
	case <-shutdownCtx.Done():
		log.Warn("request server shutdown timed out; forcing stop")
		_ = httpServer.Close()
		grpcServer.Stop()
	}

	cancelWorkers()
	workersDone := make(chan struct{})
	go func() { workerWG.Wait(); close(workersDone) }()
	workerShutdownCtx, cancelWorkerShutdown := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancelWorkerShutdown()
	select {
	case <-workersDone:
		log.Info("background workers stopped")
	case <-workerShutdownCtx.Done():
		log.Warn("background worker shutdown timed out")
	}

	closeCtx, cancelClose := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelClose()
	if closeErr := dependencies.Close(closeCtx); closeErr != nil {
		log.Error("close dependencies", zap.Error(closeErr))
	}
	log.Info("location service stopped")
}
func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
func requiredEnv(key string, log *zap.Logger) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		log.Error("required environment variable is missing", zap.String("key", key))
		os.Exit(1)
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
func envDuration(key string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(os.Getenv(key))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
func split(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func newRedisClient() redis.UniversalClient {
	masterName := strings.TrimSpace(os.Getenv("REDIS_MASTER_NAME"))
	sentinelAddrs := split(os.Getenv("REDIS_SENTINEL_ADDRS"))
	if masterName != "" && len(sentinelAddrs) > 0 {
		return redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:       masterName,
			SentinelAddrs:    sentinelAddrs,
			SentinelPassword: os.Getenv("REDIS_SENTINEL_PASSWORD"),
			Password:         os.Getenv("REDIS_PASSWORD"),
			DB:               envIntAllowZero("REDIS_DB", 0),
			PoolSize:         envInt("REDIS_POOL_SIZE", 20),
			MinIdleConns:     envInt("REDIS_MIN_IDLE_CONNS", 5),
		})
	}
	return redis.NewClient(
		&redis.Options{
			Addr:         env("REDIS_ADDR", "localhost:6379"),
			Password:     os.Getenv("REDIS_PASSWORD"),
			DB:           envIntAllowZero("REDIS_DB", 0),
			PoolSize:     envInt("REDIS_POOL_SIZE", 20),
			MinIdleConns: envInt("REDIS_MIN_IDLE_CONNS", 5),
		},
	)
}

func envIntAllowZero(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil || value < 0 {
		return fallback
	}
	return value
}

func fatalWithCleanup(log *zap.Logger, dependencies *closer.Closer, message string, err error) {
	log.Error(message, zap.Error(err))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if closeErr := dependencies.Close(ctx); closeErr != nil {
		log.Error("startup cleanup failed", zap.Error(closeErr))
	}
	_ = log.Sync()
	os.Exit(1)
}
