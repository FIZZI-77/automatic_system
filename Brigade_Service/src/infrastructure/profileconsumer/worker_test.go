package profileconsumer

import (
	"strings"
	"testing"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

func TestNewValidatesConfiguration(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"no brokers", Config{Topic: "profiles.events.v1", GroupID: "group"}},
		{"blank brokers", Config{Brokers: []string{" ", "\t"}, Topic: "profiles.events.v1", GroupID: "group"}},
		{"blank topic", Config{Brokers: []string{"kafka:9092"}, Topic: " ", GroupID: "group"}},
		{"blank group", Config{Brokers: []string{"kafka:9092"}, Topic: "profiles.events.v1", GroupID: " "}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			worker, err := New(nil, tt.cfg, zap.NewNop())
			if err == nil || worker != nil {
				t.Fatalf("New() = (%v, %v), want nil worker and error", worker, err)
			}
		})
	}
}

func TestNewAppliesWorkerDefaultsAndCleansBrokers(t *testing.T) {
	worker, err := New(nil, Config{
		Brokers: []string{" ", " kafka:9092 ", ""},
		Topic:   "profiles.events.v1", GroupID: "group",
		Workers: -1, RetryWorkers: 0,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	if got := len(worker.readers); got != 4 {
		t.Errorf("main readers = %d, want 4", got)
	}
	if got := len(worker.retryReaders); got != 2 {
		t.Errorf("retry readers = %d, want 2", got)
	}
	if got := worker.readers[0].Config().Brokers; len(got) != 1 || got[0] != "kafka:9092" {
		t.Errorf("brokers = %v, want [kafka:9092]", got)
	}
}

func TestNewPreservesExplicitWorkerCounts(t *testing.T) {
	worker, err := New(nil, Config{
		Brokers: []string{"kafka:9092"}, Topic: "profiles.events.v1", GroupID: "group",
		Workers: 7, RetryWorkers: 3,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	if len(worker.readers) != 7 || len(worker.retryReaders) != 3 {
		t.Fatalf("reader counts = (%d, %d), want (7, 3)", len(worker.readers), len(worker.retryReaders))
	}
}

func TestRetryCount(t *testing.T) {
	tests := []struct {
		name    string
		headers []kafka.Header
		want    int
	}{
		{"missing", nil, 0},
		{"valid", []kafka.Header{{Key: retryHeader, Value: []byte("3")}}, 3},
		{"case insensitive", []kafka.Header{{Key: "X-Retry-Count", Value: []byte("2")}}, 2},
		{"malformed", []kafka.Header{{Key: retryHeader, Value: []byte("nope")}}, 0},
		{"negative", []kafka.Header{{Key: retryHeader, Value: []byte("-4")}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryCount(tt.headers); got != tt.want {
				t.Fatalf("retryCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestUpsertHeaderReplacesCaseInsensitivelyWithoutMutatingInput(t *testing.T) {
	input := []kafka.Header{
		{Key: "trace-id", Value: []byte("trace")},
		{Key: "X-Retry-Count", Value: []byte("1")},
		{Key: retryHeader, Value: []byte("2")},
	}
	got := upsertHeader(input, retryHeader, "3")
	if len(got) != 2 {
		t.Fatalf("header count = %d, want 2", len(got))
	}
	if string(got[1].Value) != "3" || got[1].Key != retryHeader {
		t.Fatalf("replacement header = %#v", got[1])
	}
	if string(input[1].Value) != "1" || string(input[2].Value) != "2" {
		t.Fatal("upsertHeader mutated its input")
	}
}

func TestTruncateBoundaries(t *testing.T) {
	if got := truncate("abc", 3); got != "abc" {
		t.Fatalf("equal length = %q", got)
	}
	if got := truncate("abcd", 3); got != "abc" {
		t.Fatalf("over limit = %q", got)
	}
	if got := truncate("", 0); got != "" {
		t.Fatalf("empty = %q", got)
	}
	long := strings.Repeat("x", 1001)
	if got := truncate(long, 1000); len(got) != 1000 {
		t.Fatalf("length = %d, want 1000", len(got))
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	worker, err := New(nil, Config{
		Brokers: []string{"kafka:9092"}, Topic: "profiles.events.v1", GroupID: "group",
		Workers: 1, RetryWorkers: 1,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err = worker.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err = worker.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
