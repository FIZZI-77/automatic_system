package repository

import (
	"auth/models"
	"context"
	"database/sql"
	"fmt"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("auth_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %v", err)
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}

	if err = db.PingContext(ctx); err != nil {
		t.Fatalf("failed to ping db: %v", err)
	}

	runMigrations(t, db)

	cleanup := func() {
		_ = db.Close()
		_ = container.Terminate(ctx)
	}

	return db, cleanup
}

func runMigrations(t *testing.T, db *sql.DB) {
	t.Helper()

	migrationsDir := "../../../scheme"

	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("failed to set goose dialect: %v", err)
	}

	if err := goose.Up(db, migrationsDir); err != nil {
		t.Fatalf("failed to apply goose migrations from %s: %v", migrationsDir, err)
	}
}

func createTestUser(t *testing.T, repo *Repo) uuid.UUID {
	t.Helper()

	userID, err := repo.CreateUser(context.Background(), &models.User{
		Email:         fmt.Sprintf("user-%s@example.com", uuid.New().String()),
		Username:      fmt.Sprintf("user_%s", uuid.New().String()[:8]),
		PasswordHash:  "password-hash",
		IsActive:      true,
		EmailVerified: false,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	return userID
}

func createTestSession(t *testing.T, repo *Repo, userID uuid.UUID) uuid.UUID {
	t.Helper()

	sessionID, err := repo.CreateSession(context.Background(), &models.Session{
		UserID:    userID,
		ClientID:  "web-client",
		IP:        "127.0.0.1",
		UserAgent: "Mozilla/5.0",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create test session: %v", err)
	}

	return sessionID
}

func createTestRefreshToken(t *testing.T, repo *Repo, userID uuid.UUID, sessionID uuid.UUID) string {
	t.Helper()

	tokenHash := fmt.Sprintf("refresh-token-hash-%s", uuid.New().String())

	err := repo.CreateToken(context.Background(), &models.RefreshToken{
		UserID:    userID,
		SessionID: sessionID,
		TokenHash: tokenHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create test refresh token: %v", err)
	}

	return tokenHash
}

func createTestOneTimeToken(t *testing.T, repo *Repo, userID uuid.UUID, tokenType models.TokenType) string {
	t.Helper()

	tokenHash := fmt.Sprintf("one-time-token-hash-%s", uuid.New().String())

	err := repo.CreateOneTimeToken(context.Background(), &models.OneTimeToken{
		UserID:    userID,
		TokenHash: tokenHash,
		Type:      tokenType,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create test one-time token: %v", err)
	}

	return tokenHash
}
