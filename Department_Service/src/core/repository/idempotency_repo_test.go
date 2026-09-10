package repository

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestIdempotencyRepository_BeginCompleteReplay(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()

	record, acquired, err := repo.BeginIdempotency(ctx, "actor", "CreateDepartment", "key-1", "hash-1", time.Hour)
	if err != nil {
		t.Fatalf("begin idempotency failed: %v", err)
	}
	if !acquired {
		t.Fatal("expected acquired true")
	}
	if record.Status != "PROCESSING" {
		t.Fatalf("expected processing status, got %s", record.Status)
	}

	response := []byte(`{"ok":true}`)
	if err = repo.CompleteIdempotency(ctx, "actor", "CreateDepartment", "key-1", response, "department", "00000000-0000-0000-0000-000000000001"); err != nil {
		t.Fatalf("complete idempotency failed: %v", err)
	}

	record, acquired, err = repo.BeginIdempotency(ctx, "actor", "CreateDepartment", "key-1", "hash-1", time.Hour)
	if err != nil {
		t.Fatalf("replay idempotency failed: %v", err)
	}
	if acquired {
		t.Fatal("expected acquired false")
	}
	if record.Status != "COMPLETED" {
		t.Fatalf("expected completed status, got %s", record.Status)
	}
	var got map[string]bool
	if err = json.Unmarshal(record.Response, &got); err != nil {
		t.Fatalf("unmarshal cached response failed: %v", err)
	}
	if !got["ok"] {
		t.Fatalf("expected cached ok response, got %s", record.Response)
	}
}

func TestIdempotencyRepository_Fail(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()

	_, acquired, err := repo.BeginIdempotency(ctx, "actor", "UpdateDepartment", "key-2", "hash-2", time.Hour)
	if err != nil {
		t.Fatalf("begin idempotency failed: %v", err)
	}
	if !acquired {
		t.Fatal("expected acquired true")
	}

	if err = repo.FailIdempotency(ctx, "actor", "UpdateDepartment", "key-2", errors.New("boom")); err != nil {
		t.Fatalf("fail idempotency failed: %v", err)
	}

	record, acquired, err := repo.BeginIdempotency(ctx, "actor", "UpdateDepartment", "key-2", "hash-2", time.Hour)
	if err != nil {
		t.Fatalf("replay failed idempotency failed: %v", err)
	}
	if acquired {
		t.Fatal("expected acquired false")
	}
	if record.Status != "FAILED" {
		t.Fatalf("expected failed status, got %s", record.Status)
	}
	if !record.Error.Valid || record.Error.String != "boom" {
		t.Fatalf("expected boom error, got %#v", record.Error)
	}
}
