package handler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"file/models"
	"file/src/core/repository"
	"file/src/core/service"
	filev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/file/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestResourceLinkCapabilityAndMixedOwnerList(t *testing.T) {
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
	schema := "security_files_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
			t.Fatal(err)
		}
	}
	repo := repository.New(scoped, scoped)
	owner, other, resource := uuid.New(), uuid.New(), uuid.New()
	first, err := repo.Create(ctx, models.CreateInput{OwnerUserID: owner, Name: "own.csv", ContentType: "text/csv", Size: 4}, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.Create(ctx, models.CreateInput{OwnerUserID: other, Name: "other.csv", ContentType: "text/csv", Size: 4}, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{first.ID, second.ID} {
		if _, err = repo.Confirm(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	svc := service.New(repo, nil, time.Minute, zap.NewNop())
	h := New(svc, zap.NewNop(), "report-test-token")
	request := &filev1.LinkFileRequest{FileId: first.ID.String(), ActorUserId: owner.String(), ActorRoles: []string{"worker"}, ResourceType: "work_report", ResourceId: resource.String()}
	if _, err = h.LinkFile(ctx, request); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("public link=%v", err)
	}
	file, err := repo.Get(ctx, first.ID)
	if err != nil || file.Status != models.StatusUploaded {
		t.Fatalf("denied link changed metadata: %+v %v", file, err)
	}
	internal := metadata.NewIncomingContext(ctx, metadata.Pairs("x-report-link-token", "report-test-token"))
	if _, err = h.LinkFile(internal, request); err != nil {
		t.Fatalf("report workflow link=%v", err)
	}
	if _, err = repo.Link(ctx, second.ID, models.LinkInput{ResourceType: "work_report", ResourceID: resource}); err != nil {
		t.Fatal(err)
	}
	visible, err := svc.List(ctx, "work_report", resource, owner, false)
	if err != nil || len(visible) != 1 || visible[0].ID != first.ID {
		t.Fatalf("mixed-owner list=%v err=%v", visible, err)
	}
}
