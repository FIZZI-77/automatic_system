package completionsaga

import (
	"testing"
	"time"

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

func TestConfigDefaults(t *testing.T) {
	t.Parallel()

	config := Config{}
	if config.AttemptTimeout > 0 || config.PollInterval > 0 || config.MaxAttempts > 0 || config.BatchSize > 0 {
		t.Fatalf("zero Config = %+v, want all zero fields", config)
	}

	config = withDefaults(config)
	if config.AttemptTimeout != 10*time.Minute {
		t.Errorf("withDefaults(Config{}).AttemptTimeout = %s, want %s", config.AttemptTimeout, 10*time.Minute)
	}
	if config.PollInterval != 30*time.Second {
		t.Errorf("withDefaults(Config{}).PollInterval = %s, want %s", config.PollInterval, 30*time.Second)
	}
	if config.MaxAttempts != 3 {
		t.Errorf("withDefaults(Config{}).MaxAttempts = %d, want 3", config.MaxAttempts)
	}
	if config.BatchSize != 50 {
		t.Errorf("withDefaults(Config{}).BatchSize = %d, want 50", config.BatchSize)
	}
}
