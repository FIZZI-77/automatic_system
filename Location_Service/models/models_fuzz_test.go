package models

import (
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
)

func FuzzRecordPositionInputValidate(f *testing.F) {
	f.Add("device-1", uint64(1), 55.75, 37.61, 10.0, 90.0, 3.0, int32(1))
	f.Add("", uint64(0), 91.0, 181.0, -1.0, 360.0, -1.0, int32(2))
	f.Fuzz(
		func(
			t *testing.T,
			device string,
			sequence uint64,
			latitude, longitude, speed, heading, accuracy float64,
			version int32,
		) {
			in := &RecordPositionInput{
				EventID:        uuid.New(),
				EventVersion:   version,
				OccurredAt:     time.Now(),
				DeviceID:       device,
				VehicleID:      uuid.New(),
				BrigadeID:      uuid.New(),
				Sequence:       sequence,
				Latitude:       latitude,
				Longitude:      longitude,
				SpeedKMH:       speed,
				Heading:        heading,
				AccuracyMeters: accuracy,
			}
			err := in.Validate()
			invalid := device == "" || sequence == 0 || sequence > math.MaxInt64 || version != 1 ||
				latitude < -90 ||
				latitude > 90 ||
				longitude < -180 ||
				longitude > 180 ||
				speed < 0 ||
				heading < 0 ||
				heading >= 360 ||
				accuracy < 0
			if invalid && err == nil {
				t.Fatal("invalid telemetry accepted")
			}
		},
	)
}

func FuzzFindNearbyBrigadesInputValidate(f *testing.F) {
	f.Add(55.75, 37.61, 1000.0, int32(10))
	f.Add(91.0, 181.0, -1.0, int32(-1))
	f.Fuzz(func(t *testing.T, latitude, longitude, radius float64, limit int32) {
		in := &FindNearbyBrigadesInput{
			Latitude:     latitude,
			Longitude:    longitude,
			RadiusMeters: radius,
			Limit:        limit,
		}
		err := in.Validate()
		invalid := latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180 ||
			radius <= 0 ||
			limit < 0 ||
			limit > MaxLimit
		if invalid && err == nil {
			t.Fatal("invalid nearby query accepted")
		}
	})
}

func FuzzGeoZoneInputsValidate(f *testing.F) {
	f.Add("zone", `{"type":"Polygon","coordinates":[]}`, 55.0, 37.0)
	f.Add("", "", 91.0, 181.0)
	f.Fuzz(func(t *testing.T, name, geoJSON string, latitude, longitude float64) {
		_ = (&CreateGeoZoneInput{DepartmentID: uuid.New(), Name: name, GeoJSON: geoJSON}).Validate()
		err := (&CheckPointInZonesInput{Latitude: latitude, Longitude: longitude}).Validate()
		if (latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) && err == nil {
			t.Fatal("invalid point accepted")
		}
	})
}
