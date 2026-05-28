package integration

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	"ticket/models"
	"ticket/src/core/repository"
	"ticket/src/core/service"
)

type testApp struct {
	db      *sql.DB
	repo    *repository.Repository
	service *service.Service
	cleanup func()
}

func newTestApp(t *testing.T) *testApp {
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
			t.Skipf("skipping ticket integration tests: %v", err)
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
	runGooseMigrations(t, db)

	repo := repository.NewRepository(db)

	return &testApp{
		db:      db,
		repo:    repo,
		service: service.NewService(repo, zap.NewNop()),
		cleanup: cleanup,
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

func uniqueCode(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, uuid.NewString()[:8])
}

func stringPtr(value string) *string {
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}

func adminRoles() []string {
	return []string{"admin"}
}

func dispatcherRoles() []string {
	return []string{"dispatcher"}
}

func createIntegrationCategory(t *testing.T, app *testApp) *models.TicketCategory {
	t.Helper()

	res, err := app.service.CreateCategory(context.Background(), &models.CreateCategoryInput{
		Code:        uniqueCode("integration-category"),
		Name:        "Integration category",
		Description: stringPtr("Created by integration test"),
		ActorRoles:  adminRoles(),
	})
	if err != nil {
		t.Fatalf("create category failed: %v", err)
	}

	return res.Category
}

func createIntegrationTicket(t *testing.T, app *testApp, categoryID uuid.UUID, userID uuid.UUID) *models.Ticket {
	t.Helper()

	departmentID := uuid.New()

	res, err := app.service.CreateTicket(context.Background(), &models.CreateTicketInput{
		DepartmentID: departmentID,
		CategoryID:   categoryID,
		UserID:       userID,
		Title:        "Street light outage",
		Description:  "Street light is not working near the main entrance",
		Priority:     models.TicketPriorityHigh,
		Address:      "Integration street 1",
		Latitude:     55.751244,
		Longitude:    37.618423,
		ActorUserID:  &userID,
	})
	if err != nil {
		t.Fatalf("create ticket failed: %v", err)
	}

	return res.Ticket
}
