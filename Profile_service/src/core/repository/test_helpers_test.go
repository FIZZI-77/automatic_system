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

	"profile/models"
)

func setupTestDB(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()

	ctx := context.Background()
	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("profile_repo_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
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
		t.Fatalf("failed to open migration db: %v", err)
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
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "docker is not supported") ||
		strings.Contains(message, "cannot connect to the docker daemon") ||
		strings.Contains(message, "failed to create docker provider") ||
		strings.Contains(message, "docker daemon") ||
		strings.Contains(message, "get provider")
}

func createTestUserProfile(t *testing.T, repo *Repository) *models.UserProfile {
	t.Helper()

	userID := uuid.New()
	result, err := repo.CreateUserProfile(context.Background(), &models.CreateUserProfileInput{
		UserID:                 userID,
		FullName:               "Repo User",
		PreferredContactMethod: models.PreferredContactMethodEmail,
	})
	if err != nil {
		t.Fatalf("failed to create test user profile: %v", err)
	}
	return result.UserProfile
}

func createTestWorkProfile(t *testing.T, repo *Repository, userProfileID uuid.UUID, departmentID uuid.UUID) *models.WorkProfileDetails {
	t.Helper()

	result, err := repo.CreateWorkProfile(context.Background(), &models.CreateWorkProfileInput{
		UserProfileID: userProfileID,
		DepartmentID:  departmentID,
		Position:      "Repo engineer",
	})
	if err != nil {
		t.Fatalf("failed to create test work profile: %v", err)
	}
	return result.Details
}

func createTestCertificationType(t *testing.T, repo *Repository, requiresFile bool) *models.CertificationType {
	t.Helper()

	code := fmt.Sprintf("cert_%s", uuid.NewString()[:8])
	result, err := repo.CreateCertificationType(context.Background(), &models.CreateCertificationTypeInput{
		Code:         code,
		Name:         "Certification " + code,
		RequiresFile: requiresFile,
	})
	if err != nil {
		t.Fatalf("failed to create test certification type: %v", err)
	}
	return result.CertificationType
}

func stringPtr(value string) *string {
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}
