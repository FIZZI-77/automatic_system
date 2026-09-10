package repository

import (
	"brigade/models"
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

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

	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx := context.Background()
	container, err := postgres.Run(ctx,
		"postgis/postgis:16-3.4-alpine",
		postgres.WithDatabase("brigade_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(90*time.Second),
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

	migrationDB, err := sql.Open("pgx", connStr)
	if err != nil {
		cleanup()
		t.Fatalf("failed to open db: %v", err)
	}

	cleanup = func() {
		_ = migrationDB.Close()
		_ = container.Terminate(ctx)
	}

	waitForDB(t, ctx, migrationDB)
	runMigrations(t, migrationDB)
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		cleanup()
		t.Fatalf("failed to open pgx pool: %v", err)
	}
	cleanup = func() {
		pool.Close()
		_ = migrationDB.Close()
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

func createTestBrigade(t *testing.T, repo *Repo, departmentID uuid.UUID) *models.Brigade {
	t.Helper()

	result, err := repo.CreateBrigade(context.Background(), &models.CreateBrigadeInput{
		DepartmentID: departmentID,
		Name:         fmt.Sprintf("brigade-%s", uuid.NewString()),
		Description:  "test brigade",
	})
	if err != nil {
		t.Fatalf("failed to create test brigade: %v", err)
	}
	return result.Brigade
}

func createTestSkill(t *testing.T, repo *Repo) *models.Skill {
	t.Helper()

	code := fmt.Sprintf("skill_%s", uuid.NewString()[:8])
	result, err := repo.CreateSkill(context.Background(), &models.CreateSkillInput{
		Code: code,
		Name: "Skill " + code,
	})
	if err != nil {
		t.Fatalf("failed to create test skill: %v", err)
	}
	return result.Skill
}

func createTestMember(t *testing.T, repo *Repo, brigadeID uuid.UUID) *models.BrigadeMember {
	t.Helper()

	result, err := repo.AddBrigadeMember(context.Background(), &models.AddBrigadeMemberInput{
		BrigadeID: brigadeID,
		UserID:    uuid.New(),
		Role:      models.BrigadeMemberRoleLead,
	})
	if err != nil {
		t.Fatalf("failed to create test member: %v", err)
	}
	return result.Member
}
