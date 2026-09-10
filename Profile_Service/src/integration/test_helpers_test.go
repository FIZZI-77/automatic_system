package integration

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
	"google.golang.org/grpc/test/bufconn"

	"profile/src/core/repository"
	"profile/src/core/service"
)

type testApp struct {
	db      *pgxpool.Pool
	repo    *repository.Repository
	service *service.Service
	cleanup func()
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()

	ctx := context.Background()
	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("profile_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		skipIfDockerUnavailable(t, err)
		t.Fatalf("failed to start postgres container: %v", err)
	}

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to get connection string: %v", err)
	}

	migrationDB, err := sql.Open("pgx", connStr)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to open db: %v", err)
	}

	waitForDB(t, ctx, migrationDB)
	runGooseMigrations(t, migrationDB)

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		_ = migrationDB.Close()
		_ = container.Terminate(ctx)
		t.Fatalf("failed to create pgx pool: %v", err)
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		_ = migrationDB.Close()
		_ = container.Terminate(ctx)
		t.Fatalf("failed to ping pgx pool: %v", err)
	}

	repo := repository.NewRepository(repository.DBPools{Write: pool, Read: pool})
	profileService := service.NewService(repo, service.Dependencies{}, zap.NewNop())

	cleanup := func() {
		pool.Close()
		_ = migrationDB.Close()
		_ = container.Terminate(ctx)
	}

	return &testApp{
		db:      pool,
		repo:    repo,
		service: profileService,
		cleanup: cleanup,
	}
}

func skipIfDockerUnavailable(t *testing.T, err error) {
	t.Helper()

	message := strings.ToLower(err.Error())
	if strings.Contains(message, "docker") &&
		(strings.Contains(message, "not supported") ||
			strings.Contains(message, "cannot connect") ||
			strings.Contains(message, "not found") ||
			strings.Contains(message, "provider")) {
		t.Skipf("skipping integration test because docker is unavailable: %v", err)
	}
}

func runGooseMigrations(t *testing.T, db *sql.DB) {
	t.Helper()

	migrationsDir := filepath.Clean("../../scheme")
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("failed to set goose dialect: %v", err)
	}
	if err := goose.Up(db, migrationsDir); err != nil {
		t.Fatalf("failed to apply goose migrations from %s: %v", migrationsDir, err)
	}
}

func waitForDB(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()

	var err error
	for i := 0; i < 10; i++ {
		err = db.PingContext(ctx)
		if err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("failed to ping db: %v", err)
}

func uniqueCode(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func grpcDialer(listener *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, s string) (net.Conn, error) {
		return listener.Dial()
	}
}
