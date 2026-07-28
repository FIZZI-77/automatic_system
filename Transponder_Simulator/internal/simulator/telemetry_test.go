package simulator

import (
	"math"
	"testing"
	"time"
)

func TestNewEventUsesPointOverrides(t *testing.T) {
	speed := 18.5
	accuracy := 2.2
	cfg := Config{
		VehicleID: "vehicle", BrigadeID: "brigade", DeviceID: "device",
		DefaultSpeed: 35, AccuracyMeters: 5,
	}
	at := time.Date(2026, 7, 27, 12, 0, 0, 0, time.FixedZone("test", 3*60*60))
	event := NewEvent(cfg,
		Point{Latitude: 55, Longitude: 37, SpeedKMH: &speed, Accuracy: &accuracy},
		Point{Latitude: 56, Longitude: 37},
		42, at,
	)
	if event.EventID == "" || event.EventType != "VehiclePositionUpdated" || event.EventVersion != 1 {
		t.Fatalf("invalid envelope: %+v", event)
	}
	if event.OccurredAt.Location() != time.UTC {
		t.Fatalf("occurred_at location = %v", event.OccurredAt.Location())
	}
	if event.Payload.Sequence != 42 || event.Payload.SpeedKMH != speed || event.Payload.AccuracyMeters != accuracy {
		t.Fatalf("invalid payload: %+v", event.Payload)
	}
	if event.Payload.Heading != 0 {
		t.Fatalf("north heading = %f, want 0", event.Payload.Heading)
	}
}

func TestHeadingCardinalDirectionsAndStationary(t *testing.T) {
	origin := Point{Latitude: 0, Longitude: 0}
	tests := []struct {
		name string
		to   Point
		want float64
	}{
		{"stationary", origin, 0},
		{"north", Point{Latitude: 1, Longitude: 0}, 0},
		{"east", Point{Latitude: 0, Longitude: 1}, 90},
		{"south", Point{Latitude: -1, Longitude: 0}, 180},
		{"west", Point{Latitude: 0, Longitude: -1}, 270},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := heading(origin, tt.to); math.Abs(got-tt.want) > 0.001 {
				t.Fatalf("heading = %f, want %f", got, tt.want)
			}
		})
	}
}
