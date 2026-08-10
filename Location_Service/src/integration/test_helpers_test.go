package integration

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"location/src/core/repository"
	"location/src/core/service"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

type testApp struct {
	db      *pgxpool.Pool
	redis   *redis.Client
	repo    *repository.Repository
	service *service.Service
	cleanup func()
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := context.Background()
	postgresContainer, err := postgres.Run(
		ctx,
		"postgis/postgis:16-3.4-alpine",
		postgres.WithDatabase("location_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(90*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	postgresURL, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = postgresContainer.Terminate(ctx)
		t.Fatalf("postgres url: %v", err)
	}
	migrationDB, err := sql.Open("pgx", postgresURL)
	if err != nil {
		_ = postgresContainer.Terminate(ctx)
		t.Fatalf("open migration db: %v", err)
	}
	if err = goose.SetDialect("postgres"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	if err = goose.Up(migrationDB, filepath.Clean("../../scheme")); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	db, err := pgxpool.New(ctx, postgresURL)
	if err != nil {
		t.Fatalf("open postgres pool: %v", err)
	}
	redisContainer, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "redis:7.4-alpine",
				ExposedPorts: []string{"6379/tcp"},
				WaitingFor: wait.ForListeningPort("6379/tcp").
					WithStartupTimeout(60 * time.Second),
			},
			Started: true,
		},
	)
	if err != nil {
		db.Close()
		_ = migrationDB.Close()
		_ = postgresContainer.Terminate(ctx)
		t.Fatalf("start redis: %v", err)
	}
	host, err := redisContainer.Host(ctx)
	if err != nil {
		t.Fatalf("redis host: %v", err)
	}
	port, err := redisContainer.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatalf("redis port: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: fmt.Sprintf("%s:%s", host, port.Port())})
	if err = rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis ping: %v", err)
	}
	repo := repository.NewRepositoryFromClients(repository.DBPools{Write: db, Read: db}, rdb)
	cleanup := func() {
		_ = rdb.Close()
		db.Close()
		_ = migrationDB.Close()
		_ = redisContainer.Terminate(ctx)
		_ = postgresContainer.Terminate(ctx)
	}
	return &testApp{
		db:      db,
		redis:   rdb,
		repo:    repo,
		service: service.NewService(repo),
		cleanup: cleanup,
	}
}
