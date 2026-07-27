package simulator

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"time"
)

type Event struct {
	EventID      string    `json:"event_id"`
	EventType    string    `json:"event_type"`
	EventVersion int       `json:"event_version"`
	OccurredAt   time.Time `json:"occurred_at"`
	Payload      Position  `json:"payload"`
}

type Position struct {
	DeviceID       string  `json:"device_id"`
	VehicleID      string  `json:"vehicle_id"`
	BrigadeID      string  `json:"brigade_id"`
	Sequence       uint64  `json:"sequence"`
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
	SpeedKMH       float64 `json:"speed_kmh"`
	Heading        float64 `json:"heading"`
	AccuracyMeters float64 `json:"accuracy_meters"`
	Simulated      bool    `json:"simulated"`
}

func NewEvent(cfg Config, current Point, next Point, sequence uint64, now time.Time) Event {
	speed := cfg.DefaultSpeed
	if current.SpeedKMH != nil {
		speed = *current.SpeedKMH
	}
	accuracy := cfg.AccuracyMeters
	if current.Accuracy != nil {
		accuracy = *current.Accuracy
	}
	return Event{
		EventID:      newUUID(),
		EventType:    "VehiclePositionUpdated",
		EventVersion: 1,
		OccurredAt:   now.UTC(),
		Payload: Position{
			DeviceID: cfg.DeviceID, VehicleID: cfg.VehicleID, BrigadeID: cfg.BrigadeID,
			Sequence: sequence, Latitude: current.Latitude, Longitude: current.Longitude,
			SpeedKMH: speed, Heading: heading(current, next),
			AccuracyMeters: accuracy, Simulated: true,
		},
	}
}

func heading(from, to Point) float64 {
	if from.Latitude == to.Latitude && from.Longitude == to.Longitude {
		return 0
	}
	lat1 := from.Latitude * math.Pi / 180
	lat2 := to.Latitude * math.Pi / 180
	deltaLongitude := (to.Longitude - from.Longitude) * math.Pi / 180
	y := math.Sin(deltaLongitude) * math.Cos(lat2)
	x := math.Cos(lat1)*math.Sin(lat2) - math.Sin(lat1)*math.Cos(lat2)*math.Cos(deltaLongitude)
	result := math.Atan2(y, x) * 180 / math.Pi
	return math.Mod(result+360, 360)
}

func newUUID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return hex.EncodeToString(value[0:4]) + "-" +
		hex.EncodeToString(value[4:6]) + "-" +
		hex.EncodeToString(value[6:8]) + "-" +
		hex.EncodeToString(value[8:10]) + "-" +
		hex.EncodeToString(value[10:16])
}
