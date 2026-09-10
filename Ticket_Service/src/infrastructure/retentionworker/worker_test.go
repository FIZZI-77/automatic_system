package retentionworker

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNewRequiresDatabase(t *testing.T) {
	worker, err := New(nil, Config{}, nil)
	if err == nil || worker != nil {
		t.Fatalf("New(nil) = (%v, %v), want error", worker, err)
	}
}

func TestNewAppliesRetentionDefaults(t *testing.T) {
	worker, err := New(&pgxpool.Pool{}, Config{}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if worker.cfg.ArchiveAfter != 24*time.Hour {
		t.Fatalf("ArchiveAfter = %v", worker.cfg.ArchiveAfter)
	}
	if worker.cfg.PurgeAfter != 30*24*time.Hour {
		t.Fatalf("PurgeAfter = %v", worker.cfg.PurgeAfter)
	}
	if worker.cfg.ArchiveInterval != 5*time.Minute || worker.cfg.PurgeInterval != time.Hour {
		t.Fatalf("unexpected intervals: %+v", worker.cfg)
	}
	if worker.cfg.BatchSize != 100 {
		t.Fatalf("BatchSize = %d", worker.cfg.BatchSize)
	}
}

func TestNewRejectsPurgeBeforeArchive(t *testing.T) {
	worker, err := New(&pgxpool.Pool{}, Config{ArchiveAfter: 48 * time.Hour, PurgeAfter: 24 * time.Hour}, nil)
	if err == nil || worker != nil {
		t.Fatalf("New(invalid ages) = (%v, %v), want error", worker, err)
	}
}
