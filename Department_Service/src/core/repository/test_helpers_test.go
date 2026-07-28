package repository

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"department/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupTestDB(t *testing.T) (*pgxpool.Pool, func()) {
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
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	cleanup := func() {
		_ = container.Terminate(ctx)
	}

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		cleanup()
		t.Fatalf("failed to get connection string: %v", err)
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		cleanup()
		t.Fatalf("failed to open db: %v", err)
	}

	cleanup = func() {
		_ = db.Close()
		_ = container.Terminate(ctx)
	}

	waitForDB(t, ctx, db)
	runMigrations(t, db)

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		cleanup()
		t.Fatalf("failed to create pgx pool: %v", err)
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		cleanup()
		t.Fatalf("failed to ping pgx pool: %v", err)
	}

	cleanup = func() {
		pool.Close()
		_ = db.Close()
		_ = container.Terminate(ctx)
	}

	return pool, cleanup
}

func runMigrations(t *testing.T, db *sql.DB) {
	t.Helper()

	migrationsDir := filepath.Clean("../../../scheme")
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
	for i := 0; i < 30; i++ {
		err = db.PingContext(ctx)
		if err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("failed to ping db: %v", err)
}

func createTestDepartment(t *testing.T, repo *Repository) *models.Department {
	t.Helper()

	department, err := repo.CreateDepartment(context.Background(), &models.CreateDepartmentInput{
		Name:        "Department " + uuid.NewString(),
		Description: "test department",
	})
	if err != nil {
		t.Fatalf("failed to create test department: %v", err)
	}

	return department
}
