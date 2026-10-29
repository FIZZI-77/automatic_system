package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"file/models"
	"file/src/core/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type recoveryStorage struct {
	objectStorage
	upload func(context.Context, string, string, string, int64, time.Duration) (string, error)
	delete func(context.Context, string) error
}

func (s *recoveryStorage) UploadURL(ctx context.Context, key, contentType, checksum string, size int64, ttl time.Duration) (string, error) {
	return s.upload(ctx, key, contentType, checksum, size, ttl)
}

func (s *recoveryStorage) Delete(ctx context.Context, key string) error {
	return s.delete(ctx, key)
}

func TestPresignFailureDoesNotWriteMetadata(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("presign failed")
	store := &recoveryStorage{upload: func(context.Context, string, string, string, int64, time.Duration) (string, error) {
		return "", wantErr
	}}
	// Репозиторий не нужен: ошибка подписи должна возвращаться до любой записи БД.
	svc := New(nil, store, time.Minute, zap.NewNop())
	_, err := svc.Create(t.Context(), models.CreateInput{OwnerUserID: uuid.New(), Name: "test.csv", ContentType: "text/csv", Size: 4})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Create(presign failure) error = %v, want %v", err, wantErr)
	}
}

func TestDeletionRecoversFromStorageFailureAfterRestart(t *testing.T) {
	pool := recoveryPool(t)
	repo := repository.New(pool, pool)
	owner := uuid.New()
	file := uploadedFile(t, repo, owner)
	objectExists := true
	storageErr := errors.New("S3 unavailable")
	store := &recoveryStorage{delete: func(context.Context, string) error { return storageErr }}
	svc := New(repo, store, time.Minute, zap.NewNop())
	if err := svc.Delete(t.Context(), file.ID, owner, false); err != nil {
		t.Fatalf("Delete(unavailable S3) error = %v, want durable logical deletion", err)
	}
	if _, err := repo.Get(t.Context(), file.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("Get(deleted file) error = %v, want not found", err)
	}
	if err := svc.Delete(t.Context(), file.ID, uuid.New(), false); !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("Delete(foreign deleted file) error = %v, want permission denied", err)
	}
	if err := svc.Delete(t.Context(), file.ID, owner, false); err != nil {
		t.Fatalf("Delete(retry) error = %v, want nil", err)
	}
	if err := svc.Cleanup(t.Context()); !errors.Is(err, storageErr) {
		t.Fatalf("Cleanup(unavailable S3) error = %v, want %v", err, storageErr)
	}
	var attempts, jobs int
	if err := pool.QueryRow(t.Context(), `SELECT count(*),max(attempts) FROM file_deletion_jobs`).Scan(&jobs, &attempts); err != nil || jobs != 1 || attempts != 1 || !objectExists {
		t.Fatalf("queued deletions = (%d, attempts %d, %v), objectExists=%v, want one retained retry", jobs, attempts, err, objectExists)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE file_deletion_jobs SET not_before=now()`); err != nil {
		t.Fatal(err)
	}
	store.delete = func(context.Context, string) error { objectExists = false; return nil }
	restarted := New(repository.New(pool, pool), store, time.Minute, zap.NewNop())
	if err := restarted.Cleanup(t.Context()); err != nil {
		t.Fatalf("Cleanup(after restart) error = %v, want nil", err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM file_deletion_jobs`).Scan(&jobs); err != nil || jobs != 0 || objectExists {
		t.Fatalf("queued deletions after recovery = (%d, %v), objectExists=%v, want empty and removed object", jobs, err, objectExists)
	}
}

func TestDeletionDoesNotTouchStorageWhenDatabaseFails(t *testing.T) {
	pool := recoveryPool(t)
	repo := repository.New(pool, pool)
	owner := uuid.New()
	file := uploadedFile(t, repo, owner)
	_, err := pool.Exec(t.Context(), `CREATE FUNCTION reject_deletion() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected database failure'; END $$; CREATE TRIGGER reject_deletion BEFORE INSERT ON file_deletion_jobs FOR EACH ROW EXECUTE FUNCTION reject_deletion()`)
	if err != nil {
		t.Fatal(err)
	}
	deleted := false
	store := &recoveryStorage{delete: func(context.Context, string) error { deleted = true; return nil }}
	if err := New(repo, store, time.Minute, zap.NewNop()).Delete(t.Context(), file.ID, owner, false); err == nil {
		t.Fatal("Delete(database failure) error = nil, want failure")
	}
	stored, err := repo.Get(t.Context(), file.ID)
	if err != nil || stored.Status != models.StatusUploaded || deleted {
		t.Fatalf("Get(after failed deletion) = (%+v, %v), S3 deleted=%v, want uploaded and untouched S3", stored, err, deleted)
	}
}

func TestDeletionAcknowledgementCanBeRetried(t *testing.T) {
	pool := recoveryPool(t)
	repo := repository.New(pool, pool)
	owner := uuid.New()
	file := uploadedFile(t, repo, owner)
	releases := 0
	store := &recoveryStorage{delete: func(context.Context, string) error { releases++; return nil }}
	svc := New(repo, store, time.Minute, zap.NewNop())
	if err := svc.Delete(t.Context(), file.ID, owner, false); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(t.Context(), `CREATE FUNCTION reject_acknowledgement() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected acknowledgement failure'; END $$; CREATE TRIGGER reject_acknowledgement BEFORE DELETE ON file_deletion_jobs FOR EACH ROW EXECUTE FUNCTION reject_acknowledgement()`)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Cleanup(t.Context()); err == nil {
		t.Fatal("Cleanup(acknowledgement failure) error = nil, want failure")
	}
	jobs, err := repo.PendingDeletions(t.Context(), 10)
	if err != nil || len(jobs) != 1 || releases != 1 {
		t.Fatalf("PendingDeletions(after failed acknowledgement) = (%v, %v), S3 calls=%d, want retained task", jobs, err, releases)
	}
	if _, err := pool.Exec(t.Context(), `DROP TRIGGER reject_acknowledgement ON file_deletion_jobs`); err != nil {
		t.Fatal(err)
	}
	if err := svc.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	jobs, err = repo.PendingDeletions(t.Context(), 10)
	if err != nil || len(jobs) != 0 || releases != 2 {
		t.Fatalf("PendingDeletions(after retry) = (%v, %v), S3 calls=%d, want completed task", jobs, err, releases)
	}
}

func TestRecoveryMigrationRejectsRollbackWithPendingDeletions(t *testing.T) {
	pool := recoveryPool(t)
	repo := repository.New(pool, pool)
	file := uploadedFile(t, repo, uuid.New())
	if err := repo.QueueDeletion(t.Context(), file.ID); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../../scheme/20261029000100_add_deletion_jobs.sql")
	if err != nil {
		t.Fatal(err)
	}
	down := strings.Split(string(data), "-- +goose Down")[1]
	if _, err := pool.Exec(t.Context(), down); err == nil {
		t.Fatal("rollback with pending deletion succeeded, want failure")
	}
	if err := repo.CompleteDeletion(t.Context(), file.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), down); err != nil {
		t.Fatalf("rollback after completed deletion: %v", err)
	}
}

func TestCleanupExpiresOnlyAbandonedUploads(t *testing.T) {
	pool := recoveryPool(t)
	repo := repository.New(pool, pool)
	owner := uuid.New()
	old, err := repo.Create(t.Context(), models.CreateInput{OwnerUserID: owner, Name: "abandoned.csv", ContentType: "text/csv", Size: 4}, "old-upload")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := repo.Create(t.Context(), models.CreateInput{OwnerUserID: owner, Name: "fresh.csv", ContentType: "text/csv", Size: 4}, "fresh-upload")
	if err != nil {
		t.Fatal(err)
	}
	uploaded := uploadedFile(t, repo, owner)
	if _, err := pool.Exec(t.Context(), `UPDATE files SET created_at=now()-interval '2 hours',upload_expires_at=now()-interval '90 minutes' WHERE id=ANY($1)`, []uuid.UUID{old.ID, uploaded.ID}); err != nil {
		t.Fatal(err)
	}
	deletedKeys := []string{}
	store := &recoveryStorage{delete: func(_ context.Context, key string) error { deletedKeys = append(deletedKeys, key); return nil }}
	if err := New(repo, store, 15*time.Minute, zap.NewNop()).Cleanup(t.Context()); err != nil {
		t.Fatalf("Cleanup(abandoned upload) error = %v, want nil", err)
	}
	if len(deletedKeys) != 1 || deletedKeys[0] != old.ObjectKey {
		t.Fatalf("Cleanup deleted keys = %v, want only %s", deletedKeys, old.ObjectKey)
	}
	for _, id := range []uuid.UUID{fresh.ID, uploaded.ID} {
		if _, err := repo.Get(t.Context(), id); err != nil {
			t.Errorf("Get(retained file %s) error = %v, want nil", id, err)
		}
	}
}

func TestPendingUploadDeletionWaitsForSignedPutExpiry(t *testing.T) {
	pool := recoveryPool(t)
	repo := repository.New(pool, pool)
	owner := uuid.New()
	file, err := repo.Create(t.Context(), models.CreateInput{OwnerUserID: owner, Name: "pending.csv", ContentType: "text/csv", Size: 4}, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	deleted := false
	store := &recoveryStorage{delete: func(context.Context, string) error { deleted = true; return nil }}
	svc := New(repo, store, time.Minute, zap.NewNop())
	if err := svc.Delete(t.Context(), file.ID, owner, false); err != nil {
		t.Fatal(err)
	}
	if err := svc.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if deleted {
		t.Fatal("Cleanup(pending PUT) deleted object before signed URL expiry")
	}
}

func uploadedFile(t *testing.T, repo *repository.Repository, owner uuid.UUID) *models.File {
	t.Helper()
	file, err := repo.Create(t.Context(), models.CreateInput{OwnerUserID: owner, Name: "uploaded.csv", ContentType: "text/csv", Size: 4, UploadExpiresAt: time.Now().Add(-time.Hour)}, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	file, err = repo.Confirm(t.Context(), file.ID)
	if err != nil {
		t.Fatal(err)
	}
	return file
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
	schema := "recovery_files_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
