package integration

import (
	"auth/src/core/repository"
	"auth/src/core/service"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type testApp struct {
	db      *sql.DB
	repo    *repository.Repo
	auth    *service.AuthServiceStruct
	mail    *fakeMailService
	cleanup func()
}

type fakeMailService struct {
	mu sync.Mutex

	lastVerificationEmail string
	lastVerificationToken string

	lastPasswordResetEmail string
	lastPasswordResetToken string
}

func (m *fakeMailService) SendVerificationEmail(ctx context.Context, toEmail string, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.lastVerificationEmail = toEmail
	m.lastVerificationToken = token

	return nil
}

func (m *fakeMailService) SendPasswordResetEmail(ctx context.Context, toEmail string, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.lastPasswordResetEmail = toEmail
	m.lastPasswordResetToken = token

	return nil
}

func (m *fakeMailService) getVerificationToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.lastVerificationToken
}

func (m *fakeMailService) getPasswordResetToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.lastPasswordResetToken
}

func newTestApp(t *testing.T) *testApp {
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
		_ = container.Terminate(ctx)
		t.Fatalf("failed to get connection string: %v", err)
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to open db: %v", err)
	}

	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		_ = container.Terminate(ctx)
		t.Fatalf("failed to ping db: %v", err)
	}

	runGooseMigrations(t, db)

	repo := repository.NewRepo(db)
	mail := &fakeMailService{}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		_ = db.Close()
		_ = container.Terminate(ctx)
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	authService := service.NewAuthServiceStruct(
		repo,
		privateKey,
		"integration-test-key",
		mail,
		zap.NewNop(),
	)

	cleanup := func() {
		_ = db.Close()
		_ = container.Terminate(ctx)
	}

	return &testApp{
		db:      db,
		repo:    repo,
		auth:    authService,
		mail:    mail,
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

func uniqueEmail() string {
	return fmt.Sprintf("user-%d@example.com", time.Now().UnixNano())
}
