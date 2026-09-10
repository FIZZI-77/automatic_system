package repository

import (
	"testing"
	"time"

	"location/models"

	"github.com/google/uuid"
)

func TestDecodeCurrentLocationCalculatesSignalStatus(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	repo := NewCurrentLocationRepoWithConfig(
		nil,
		CurrentLocationRepoConfig{StaleAfter: 10 * time.Second, OfflineAfter: 30 * time.Second},
	)
	repo.now = func() time.Time { return now }

	values := validLocationValues(now.Add(-20 * time.Second))
	location, err := repo.decodeCurrentLocation(values)
	if err != nil {
		t.Fatalf("decode current location: %v", err)
	}
	if location.SignalStatus != models.SignalStatusStale {
		t.Fatalf("signal status = %s, want %s", location.SignalStatus, models.SignalStatusStale)
	}

	values = validLocationValues(now.Add(-40 * time.Second))
	location, err = repo.decodeCurrentLocation(values)
	if err != nil {
		t.Fatalf("decode offline current location: %v", err)
	}
	if location.SignalStatus != models.SignalStatusOffline {
		t.Fatalf("signal status = %s, want %s", location.SignalStatus, models.SignalStatusOffline)
	}
}

func TestCurrentLocationConfigKeepsStatePastOfflineThreshold(t *testing.T) {
	repo := NewCurrentLocationRepoWithConfig(nil, CurrentLocationRepoConfig{
		CurrentLocationTTL: 5 * time.Second,
		StaleAfter:         20 * time.Second,
		OfflineAfter:       10 * time.Second,
	})
	if repo.cfg.OfflineAfter <= repo.cfg.StaleAfter {
		t.Fatalf(
			"offline threshold %s must be after stale threshold %s",
			repo.cfg.OfflineAfter,
			repo.cfg.StaleAfter,
		)
	}
	if repo.cfg.CurrentLocationTTL <= repo.cfg.OfflineAfter {
		t.Fatalf(
			"ttl %s must outlive offline threshold %s",
			repo.cfg.CurrentLocationTTL,
			repo.cfg.OfflineAfter,
		)
	}
}

func validLocationValues(receivedAt time.Time) map[string]string {
	staleAfter := receivedAt.Add(10 * time.Second)
	return map[string]string{
		"event_id":        uuid.NewString(),
		"device_id":       "device-1",
		"vehicle_id":      uuid.NewString(),
		"brigade_id":      uuid.NewString(),
		"sequence":        "42",
		"latitude":        "55.7558",
		"longitude":       "37.6173",
		"speed_kmh":       "20",
		"heading":         "120",
		"accuracy_meters": "3.5",
		"altitude_meters": "",
		"simulated":       "false",
		"recorded_at":     receivedAt.Format(time.RFC3339Nano),
		"received_at":     receivedAt.Format(time.RFC3339Nano),
		"signal_status":   string(models.SignalStatusOnline),
		"stale_after":     staleAfter.Format(time.RFC3339Nano),
	}
}
