package outboxrelay

import (
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNewValidationAndDefaults(t *testing.T) {
	for _, cfg := range []Config{{Topic: "events"}, {Brokers: []string{" "}, Topic: "events"}, {Brokers: []string{"kafka:9092"}, Topic: " "}} {
		if worker, err := New(nil, cfg, zap.NewNop()); err == nil || worker != nil {
			t.Fatalf("New(%+v) = (%v, %v), want error", cfg, worker, err)
		}
	}
	worker, err := New(nil, Config{Brokers: []string{" ", " kafka:9092 "}, Topic: "events"}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	if worker.cfg.BatchSize != defaultBatchSize || worker.cfg.PollInterval != defaultPollInterval || worker.cfg.MaxAttempts != defaultMaxAttempts || worker.cfg.LockTimeout != defaultLockTimeout || worker.cfg.WorkerCount != defaultWorkerCount {
		t.Fatalf("defaults not applied: %+v", worker.cfg)
	}
	if len(worker.cfg.Brokers) != 1 || worker.cfg.Brokers[0] != "kafka:9092" {
		t.Fatalf("brokers not cleaned: %v", worker.cfg.Brokers)
	}
}

func TestNewPreservesPositiveConfiguration(t *testing.T) {
	cfg := Config{Brokers: []string{"kafka:9092"}, Topic: "events", BatchSize: 9, PollInterval: 2 * time.Second, MaxAttempts: 3, LockTimeout: time.Minute, WorkerCount: 7}
	worker, err := New(nil, cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	if worker.cfg.BatchSize != 9 || worker.cfg.PollInterval != 2*time.Second || worker.cfg.MaxAttempts != 3 || worker.cfg.LockTimeout != time.Minute || worker.cfg.WorkerCount != 7 {
		t.Fatalf("configuration changed: %+v", worker.cfg)
	}
}

func TestTruncateBoundaries(t *testing.T) {
	if truncate("abc", 3) != "abc" || truncate("abcd", 3) != "abc" || truncate("", 0) != "" {
		t.Fatal("truncate returned an unexpected boundary result")
	}
	if got := truncate(strings.Repeat("x", 2001), 2000); len(got) != 2000 {
		t.Fatalf("length = %d, want 2000", len(got))
	}
}
