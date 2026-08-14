package repository

import (
	"testing"
	"time"
)

func TestNewRepositoryFromClientsWithConfigPassesSignalThresholds(t *testing.T) {
	configured := NewRepositoryFromClientsWithConfig(
		DBPools{},
		nil,
		CurrentLocationRepoConfig{
			StaleAfter:   5 * time.Minute,
			OfflineAfter: 10 * time.Minute,
		},
	)

	current, ok := configured.CurrentLocationRepo.(*CurrentLocationRepoStruct)
	if !ok {
		t.Fatalf("current location repository has type %T", configured.CurrentLocationRepo)
	}
	if current.cfg.StaleAfter != 5*time.Minute {
		t.Fatalf("stale threshold = %s, want 5m", current.cfg.StaleAfter)
	}
	if current.cfg.OfflineAfter != 10*time.Minute {
		t.Fatalf("offline threshold = %s, want 10m", current.cfg.OfflineAfter)
	}
}
