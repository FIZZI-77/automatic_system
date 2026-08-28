package partitionmanager

import (
	"testing"

	"go.uber.org/zap"
)

func TestNewRejectsNilDatabase(t *testing.T) {
	t.Parallel()

	worker, err := New(nil, Config{}, zap.NewNop())
	if err == nil {
		t.Errorf("New(nil, Config{}) error = nil, want non-nil")
	}
	if worker != nil {
		t.Errorf("New(nil, Config{}) worker = %v, want nil", worker)
	}
}
