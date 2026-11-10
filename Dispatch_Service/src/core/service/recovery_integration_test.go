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
	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type releaseClient struct {
	brigadev1.BrigadeServiceClient
	setStatus func(context.Context, *brigadev1.SetBrigadeStatusRequest) error
}

func (c *releaseClient) SetBrigadeStatus(ctx context.Context, in *brigadev1.SetBrigadeStatusRequest, _ ...grpc.CallOption) (*brigadev1.SetBrigadeStatusResponse, error) {
	return &brigadev1.SetBrigadeStatusResponse{}, c.setStatus(ctx, in)
}

func TestCancelledReservationRecoversAfterRestart(t *testing.T) {
	pool := recoveryPool(t)
	repo := repository.New(pool, pool)
	actor, cancellingActor, department, brigade := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	op := reservedOperation(t, repo, actor, department, brigade)
	actorCtx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("x-actor-roles", "dispatcher", "x-actor-user-id", cancellingActor.String(), "x-actor-department-id", department.String()))
	busy := true
	client := &releaseClient{setStatus: func(context.Context, *brigadev1.SetBrigadeStatusRequest) error {
		return status.Error(codes.Unavailable, "brigade unavailable")
	}}
	svc := &Service{repo: repo, deps: Dependencies{Brigades: client}, log: zap.NewNop()}
	cancelled, err := svc.Cancel(actorCtx, &models.CancelInput{ID: op.ID, CancelledBy: cancellingActor, ExpectedVersion: op.Version})
	if err != nil || cancelled.Status != models.StatusCancelled || !cancelled.ReleasePending {
		t.Fatalf("Cancel(unavailable brigade) = (%+v, %v), want cancelled with pending compensation", cancelled, err)
	}
	if _, err := repo.Create(t.Context(), models.CreateOperationInput{TicketID: op.TicketID, DepartmentID: department, CategoryID: uuid.New(), RequestedBy: actor, Mode: models.ModeManual, TTL: time.Minute}); !errors.Is(err, models.ErrConflict) {
		t.Fatalf("Create(same ticket before release) error = %v, want conflict", err)
	}
	other, err := repo.Create(t.Context(), models.CreateOperationInput{TicketID: uuid.New(), DepartmentID: department, CategoryID: uuid.New(), RequestedBy: actor, Mode: models.ModeManual, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SetReserved(t.Context(), other.ID, brigade, other.Version); !errors.Is(err, models.ErrConflict) {
		t.Fatalf("SetReserved(brigade before release) error = %v, want conflict", err)
	}
	client.setStatus = func(ctx context.Context, in *brigadev1.SetBrigadeStatusRequest) error {
		md, _ := metadata.FromOutgoingContext(ctx)
		if in.GetChangedByUserId() != cancellingActor.String() || strings.Join(md.Get("x-actor-department-id"), "") != department.String() {
			t.Errorf("release actor/department = (%s, %v), want (%s, %s)", in.GetChangedByUserId(), md.Get("x-actor-department-id"), cancellingActor, department)
		}
		busy = false
		return nil
	}
	// Новый экземпляр не содержит никакого состояния предыдущего запроса.
	restarted := &Service{repo: repository.New(pool, pool), deps: Dependencies{Brigades: client}, log: zap.NewNop()}
	if err := restarted.Cleanup(t.Context()); err != nil {
		t.Fatalf("Cleanup(after restart) error = %v, want nil", err)
	}
	stored, err := repo.Get(t.Context(), op.ID)
	if err != nil || stored.ReleasePending || busy {
		t.Fatalf("Get(after recovery) = (%+v, %v), busy=%v, want released reservation", stored, err, busy)
	}
	if _, err := repo.SetReserved(t.Context(), other.ID, brigade, other.Version); err != nil {
		t.Fatalf("SetReserved(after release) error = %v, want nil", err)
	}
}

func TestReleaseRemainsPendingUntilDatabaseAcknowledges(t *testing.T) {
	pool := recoveryPool(t)
	repo := repository.New(pool, pool)
	actor, department := uuid.New(), uuid.New()
	op := reservedOperation(t, repo, actor, department, uuid.New())
	if _, err := repo.Cancel(t.Context(), op.ID, actor, "test cancellation", op.Version); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(t.Context(), `CREATE FUNCTION reject_release() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.release_pending AND NOT NEW.release_pending THEN RAISE EXCEPTION 'injected acknowledgement failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_release BEFORE UPDATE ON dispatch_operations FOR EACH ROW EXECUTE FUNCTION reject_release()`)
	if err != nil {
		t.Fatal(err)
	}
	releases := 0
	client := &releaseClient{setStatus: func(context.Context, *brigadev1.SetBrigadeStatusRequest) error { releases++; return nil }}
	svc := &Service{repo: repo, deps: Dependencies{Brigades: client}, log: zap.NewNop()}
	if err := svc.Cleanup(t.Context()); err == nil {
		t.Fatal("Cleanup(database acknowledgement failure) error = nil, want failure")
	}
	stored, err := repo.Get(t.Context(), op.ID)
	if err != nil || !stored.ReleasePending || releases != 1 {
		t.Fatalf("Get(after acknowledgement failure) = (%+v, %v), releases=%d, want pending and one release", stored, err, releases)
	}
	if _, err := pool.Exec(t.Context(), `DROP TRIGGER reject_release ON dispatch_operations`); err != nil {
		t.Fatal(err)
	}
	if err := svc.Cleanup(t.Context()); err != nil {
		t.Fatalf("Cleanup(retry acknowledgement) error = %v, want nil", err)
	}
	stored, err = repo.Get(t.Context(), op.ID)
	if err != nil || stored.ReleasePending || releases != 2 {
		t.Fatalf("Get(after retry) = (%+v, %v), releases=%d, want completed and two idempotent releases", stored, err, releases)
	}
}

func TestCancellationCannotRaceLockedConfirmation(t *testing.T) {
	pool := recoveryPool(t)
	repo := repository.New(pool, pool)
	actor, department := uuid.New(), uuid.New()
	op := reservedOperation(t, repo, actor, department, uuid.New())
	release, acquired, err := repo.TryOperationLock(t.Context(), op.ID)
	if err != nil || !acquired {
		t.Fatalf("TryOperationLock() = (%v, %v), want acquired", acquired, err)
	}
	defer release()
	svc := &Service{repo: repo, log: zap.NewNop()}
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("x-actor-roles", "admin"))
	if _, err := svc.Cancel(ctx, &models.CancelInput{ID: op.ID, CancelledBy: actor, ExpectedVersion: op.Version}); !errors.Is(err, models.ErrConflict) {
		t.Fatalf("Cancel(locked operation) error = %v, want conflict", err)
	}
	stored, err := repo.Get(t.Context(), op.ID)
	if err != nil || stored.Status != models.StatusReserved || stored.ReleasePending {
		t.Fatalf("Get(locked operation) = (%+v, %v), want unchanged reservation", stored, err)
	}
}

func TestRecoveryMigrationRejectsRollbackWithPendingRelease(t *testing.T) {
	pool := recoveryPool(t)
	repo := repository.New(pool, pool)
	actor, department := uuid.New(), uuid.New()
	op := reservedOperation(t, repo, actor, department, uuid.New())
	if _, err := repo.Cancel(t.Context(), op.ID, actor, "test", op.Version); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../../scheme/20261029000100_add_release_compensation.sql")
	if err != nil {
		t.Fatal(err)
	}
	down := strings.Split(string(data), "-- +goose Down")[1]
	if _, err := pool.Exec(t.Context(), down); err == nil {
		t.Fatal("rollback with pending release succeeded, want failure")
	}
	if err := repo.CompleteRelease(t.Context(), op.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), down); err != nil {
		t.Fatalf("rollback after completed release: %v", err)
	}
}

func reservedOperation(t *testing.T, repo *repository.Repository, actor, department, brigade uuid.UUID) *models.Operation {
	t.Helper()
	op, err := repo.Create(t.Context(), models.CreateOperationInput{TicketID: uuid.New(), DepartmentID: department, CategoryID: uuid.New(), RequestedBy: actor, Mode: models.ModeManual, TTL: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	op, err = repo.SetReserved(t.Context(), op.ID, brigade, op.Version)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func recoveryPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("RECOVERY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set RECOVERY_TEST_DATABASE_URL for isolated PostgreSQL recovery tests")
	}
	base, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "recovery_dispatch_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := base.Exec(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		base.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := base.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
		base.Close()
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	paths, err := filepath.Glob("../../../scheme/*.sql")
	if err != nil || len(paths) == 0 {
		t.Fatalf("migration discovery = (%v, %v), want SQL files", paths, err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), strings.Split(string(data), "-- +goose Down")[0]); err != nil {
			t.Fatalf("apply %s: %v", path, err)
		}
	}
	return pool
}
