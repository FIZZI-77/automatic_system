package outboxrelay

import (
	"errors"
	"testing"
)

func TestRequireLeaseRejectsStaleOwner(t *testing.T) {
	t.Parallel()
	if err := requireLease(1, nil); err != nil {
		t.Errorf("requireLease(1, nil) error = %v, want nil", err)
	}
	if err := requireLease(0, nil); !errors.Is(err, errLeaseLost) {
		t.Errorf("requireLease(0, nil) error = %v, want %v", err, errLeaseLost)
	}
	wantErr := errors.New("database unavailable")
	if err := requireLease(0, wantErr); !errors.Is(err, wantErr) {
		t.Errorf("requireLease(0, database error) error = %v, want %v", err, wantErr)
	}
}

func TestCleanBrokers(t *testing.T) {
	t.Parallel()
	got := cleanBrokers([]string{" kafka-1:9092 ", "", "\t", "kafka-2:9092"})
	if len(got) != 2 || got[0] != "kafka-1:9092" || got[1] != "kafka-2:9092" {
		t.Errorf("cleanBrokers() = %#v, want two normalized brokers", got)
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()
	if got := truncate("dispatch-error", 8); got != "dispatch" {
		t.Errorf("truncate(dispatch-error, 8) = %q, want %q", got, "dispatch")
	}
}
