//go:build integration

package repository

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Each test applies the real migrations to its own schema, never to application tables.
func peripheralPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("PERIPHERAL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PERIPHERAL_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migrations, err := filepath.Glob("../../../scheme/*.sql")
	if err != nil || len(migrations) == 0 {
		t.Fatalf("find migrations = %v, %v", migrations, err)
	}
	for _, file := range migrations {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		up, _, _ := strings.Cut(string(data), "-- +goose Down")
		if _, err := pool.Exec(ctx, up); err != nil {
			t.Fatalf("apply migration %s: %v", file, err)
		}
	}
	return pool
}
