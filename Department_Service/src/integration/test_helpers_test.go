package integration

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"department/src/core/repository"
	"department/src/core/service"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type testApp struct {
	db         *pgxpool.Pool
	repo       *repository.Repository
	department *service.DepartmentServiceStruct
	cleanup    func()
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()

	ctx := context.Background()
	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("department_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to get connection string: %v", err)
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to open db: %v", err)
	}

	waitForDB(t, ctx, db)
	runGooseMigrations(t, db)

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		_ = db.Close()
		_ = container.Terminate(ctx)
		t.Fatalf("failed to create pgx pool: %v", err)
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		_ = db.Close()
		_ = container.Terminate(ctx)
		t.Fatalf("failed to ping pgx pool: %v", err)
	}

	repo := repository.NewRepository(repository.DBPools{Write: pool, Read: pool})
	departmentService := service.NewDepartmentServiceStruct(repo, zap.NewNop())

	cleanup := func() {
		pool.Close()
		_ = db.Close()
		_ = container.Terminate(ctx)
	}

	return &testApp{
		db:         pool,
		repo:       repo,
		department: departmentService,
		cleanup:    cleanup,
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

func uniqueDepartmentName() string {
	return fmt.Sprintf("department-%d", time.Now().UnixNano())
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
