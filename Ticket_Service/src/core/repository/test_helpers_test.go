package repository

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"ticket/models"
)

func setupTestDB(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()

	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("ticket_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		if isDockerProviderUnavailable(err) {
			t.Skipf("skipping repository integration tests: %v", err)
		}

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

func isDockerProviderUnavailable(err error) bool {
	message := err.Error()
	return strings.Contains(message, "Docker is not supported") ||
		strings.Contains(message, "Cannot connect to the Docker daemon") ||
		strings.Contains(message, "failed to create Docker provider") ||
		strings.Contains(message, "docker daemon")
}

func createTestCategory(t *testing.T, repo *Repository) *models.TicketCategory {
	t.Helper()

	category, err := repo.CreateCategory(context.Background(), &models.CreateCategoryInput{
		Code:        fmt.Sprintf("category_%s", uuid.New().String()[:8]),
		Name:        "Test Category",
		Description: stringPtr("Test category description"),
	})
	if err != nil {
		t.Fatalf("failed to create test category: %v", err)
	}

	return category
}

func createTestTicket(t *testing.T, repo *Repository, categoryID uuid.UUID) *models.Ticket {
	t.Helper()

	ticket, err := repo.CreateTicket(context.Background(), &models.CreateTicketInput{
		DepartmentID: uuid.New(),
		CategoryID:   categoryID,
		UserID:       uuid.New(),
		Title:        "Pipe leak",
		Description:  "Pipe leak in building basement",
		Priority:     models.TicketPriorityMedium,
		Address:      "Main street 1",
		Latitude:     55.751244,
		Longitude:    37.618423,
	})
	if err != nil {
		t.Fatalf("failed to create test ticket: %v", err)
	}

	return ticket
}

func stringPtr(value string) *string {
	return &value
}
