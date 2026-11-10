package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dispatch/models"
	"dispatch/src/core/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/metadata"
)

func TestDepartmentScopeAtStorageBoundary(t *testing.T) {
	dsn := os.Getenv("SECURITY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set SECURITY_TEST_DATABASE_URL for isolated PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	schema := "security_dispatch_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	scoped, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer scoped.Close()
	paths, err := filepath.Glob("../../../scheme/*.sql")
	if err != nil || len(paths) == 0 {
		t.Fatalf("migrations: %v", err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = scoped.Exec(ctx, strings.Split(string(data), "-- +goose Down")[0]); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	repo := repository.New(scoped, scoped)
	own, other, actor := uuid.New(), uuid.New(), uuid.New()
	first, err := repo.Create(ctx, models.CreateOperationInput{TicketID: uuid.New(), DepartmentID: own, CategoryID: uuid.New(), RequestedBy: actor, Mode: models.ModeManual, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := repo.Create(ctx, models.CreateOperationInput{TicketID: uuid.New(), DepartmentID: other, CategoryID: uuid.New(), RequestedBy: uuid.New(), Mode: models.ModeManual, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{repo: repo}
	actorCtx := metadata.NewIncomingContext(ctx, metadata.Pairs("x-actor-user-id", actor.String(), "x-actor-roles", "dispatcher", "x-actor-department-id", own.String()))
	if _, err = svc.Get(actorCtx, foreign.ID); !errors.Is(err, models.ErrForbidden) {
		t.Fatalf("foreign Get=%v", err)
	}
	if _, err = svc.Cancel(actorCtx, &models.CancelInput{ID: foreign.ID, CancelledBy: actor, ExpectedVersion: foreign.Version}); !errors.Is(err, models.ErrForbidden) {
		t.Fatalf("foreign Cancel=%v", err)
	}
	unchanged, err := repo.Get(ctx, foreign.ID)
	if err != nil || unchanged.Status != models.StatusPending || unchanged.Version != foreign.Version {
		t.Fatalf("foreign operation changed: %+v %v", unchanged, err)
	}
	if _, err = scoped.Exec(ctx, "UPDATE dispatch_operations SET status='RESERVED',brigade_id=$2 WHERE id=$1", foreign.ID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Confirm(actorCtx, &models.ConfirmInput{ID: foreign.ID, ConfirmedBy: actor, ExpectedVersion: foreign.Version}); !errors.Is(err, models.ErrForbidden) {
		t.Fatalf("foreign Confirm=%v", err)
	}
	unchanged, err = repo.Get(ctx, foreign.ID)
	if err != nil || unchanged.Status != models.StatusReserved || unchanged.Version != foreign.Version {
		t.Fatalf("foreign Confirm changed state: %+v %v", unchanged, err)
	}
	items, total, err := svc.List(actorCtx, &models.ListInput{DepartmentID: &other, Limit: 1})
	if err != nil || total != 1 || len(items) != 1 || items[0].ID != first.ID {
		t.Fatalf("scoped list=%v total=%d err=%v", items, total, err)
	}
	if _, err = svc.Cancel(actorCtx, &models.CancelInput{ID: first.ID, CancelledBy: actor, ExpectedVersion: first.Version}); err != nil {
		t.Fatalf("own Cancel=%v", err)
	}
	admin := metadata.NewIncomingContext(ctx, metadata.Pairs("x-actor-roles", "admin"))
	if _, total, err = svc.List(admin, &models.ListInput{}); err != nil || total != 2 {
		t.Fatalf("admin total=%d err=%v", total, err)
	}
}
