package models

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRecordPositionInputValidate(t *testing.T) {
	now := time.Now().UTC()
	valid := func() *RecordPositionInput {
		return &RecordPositionInput{
			EventID:        uuid.New(),
			EventVersion:   1,
			OccurredAt:     now,
			DeviceID:       "device-1",
			VehicleID:      uuid.New(),
			BrigadeID:      uuid.New(),
			Sequence:       1,
			Latitude:       55.75,
			Longitude:      37.61,
			SpeedKMH:       20,
			Heading:        180,
			AccuracyMeters: 3,
		}
	}
	tests := []struct {
		name    string
		mutate  func(*RecordPositionInput)
		wantErr bool
	}{
		{name: "valid"},
		{
			name:    "event id",
			mutate:  func(in *RecordPositionInput) { in.EventID = uuid.Nil },
			wantErr: true,
		},
		{
			name:    "event version",
			mutate:  func(in *RecordPositionInput) { in.EventVersion = 2 },
			wantErr: true,
		},
		{
			name:    "device",
			mutate:  func(in *RecordPositionInput) { in.DeviceID = "  " },
			wantErr: true,
		},
		{
			name:    "vehicle",
			mutate:  func(in *RecordPositionInput) { in.VehicleID = uuid.Nil },
			wantErr: true,
		},
		{
			name:    "brigade",
			mutate:  func(in *RecordPositionInput) { in.BrigadeID = uuid.Nil },
			wantErr: true,
		},
		{
			name:    "sequence zero",
			mutate:  func(in *RecordPositionInput) { in.Sequence = 0 },
			wantErr: true,
		},
		{
			name:    "sequence overflow",
			mutate:  func(in *RecordPositionInput) { in.Sequence = 1 << 63 },
			wantErr: true,
		},
		{
			name:    "time",
			mutate:  func(in *RecordPositionInput) { in.OccurredAt = time.Time{} },
			wantErr: true,
		},
		{
			name:    "latitude",
			mutate:  func(in *RecordPositionInput) { in.Latitude = 91 },
			wantErr: true,
		},
		{
			name:    "longitude",
			mutate:  func(in *RecordPositionInput) { in.Longitude = -181 },
			wantErr: true,
		},
		{name: "speed", mutate: func(in *RecordPositionInput) { in.SpeedKMH = -1 }, wantErr: true},
		{
			name:    "heading",
			mutate:  func(in *RecordPositionInput) { in.Heading = 360 },
			wantErr: true,
		},
		{
			name:    "accuracy",
			mutate:  func(in *RecordPositionInput) { in.AccuracyMeters = -1 },
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := valid()
			if tt.mutate != nil {
				tt.mutate(in)
			}
			if got := in.Validate(); (got != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", got, tt.wantErr)
			}
		})
	}
	var nilInput *RecordPositionInput
	if nilInput.Validate() == nil {
		t.Fatal("nil input must fail")
	}
}

func TestLocationQueryValidation(t *testing.T) {
	id := uuid.New()
	now := time.Now().UTC()
	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{
			name: "current brigade",
			err:  (&GetCurrentLocationInput{SubjectType: SubjectTypeBrigade, SubjectID: id.String()}).Validate(),
		},
		{
			name:    "current invalid type",
			err:     (&GetCurrentLocationInput{SubjectType: "BAD", SubjectID: id.String()}).Validate(),
			wantErr: true,
		},
		{name: "many", err: (&GetCurrentLocationsInput{BrigadeIDs: []uuid.UUID{id}}).Validate()},
		{name: "many empty", err: (&GetCurrentLocationsInput{}).Validate(), wantErr: true},
		{
			name: "history",
			err:  (&ListPositionHistoryInput{BrigadeID: id, From: now.Add(-time.Hour), To: now, Order: SortOrderAsc}).Validate(),
		},
		{
			name:    "history range",
			err:     (&ListPositionHistoryInput{BrigadeID: id, From: now, To: now.Add(-time.Hour)}).Validate(),
			wantErr: true,
		},
		{
			name: "nearby",
			err:  (&FindNearbyBrigadesInput{Latitude: 55, Longitude: 37, RadiusMeters: 1000}).Validate(),
		},
		{
			name:    "nearby radius",
			err:     (&FindNearbyBrigadesInput{RadiusMeters: 0}).Validate(),
			wantErr: true,
		},
		{
			name: "signals",
			err:  (&DetectLostSignalsInput{StaleBefore: now.Add(-time.Minute), OfflineBefore: now.Add(-time.Hour)}).Validate(),
		},
		{
			name: "signals order",
			err: (&DetectLostSignalsInput{
				StaleBefore:   now.Add(-time.Hour),
				OfflineBefore: now.Add(-time.Minute),
			}).Validate(),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if (tt.err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", tt.err, tt.wantErr)
			}
		})
	}
}

func TestGeoZoneValidation(t *testing.T) {
	id := uuid.New()
	name := "updated"
	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{
			name: "create",
			err:  (&CreateGeoZoneInput{DepartmentID: id, Name: "zone", GeoJSON: "{}"}).Validate(),
		},
		{name: "create empty", err: (&CreateGeoZoneInput{}).Validate(), wantErr: true},
		{name: "update", err: (&UpdateGeoZoneInput{ID: id, Name: &name}).Validate()},
		{name: "update empty", err: (&UpdateGeoZoneInput{ID: id}).Validate(), wantErr: true},
		{name: "delete", err: (&DeleteGeoZoneInput{ID: id}).Validate()},
		{
			name:    "list page",
			err:     (&ListGeoZonesInput{Limit: MaxLimit + 1}).Validate(),
			wantErr: true,
		},
		{name: "point", err: (&CheckPointInZonesInput{Latitude: -90, Longitude: 180}).Validate()},
		{
			name:    "point invalid",
			err:     (&CheckPointInZonesInput{Latitude: -91}).Validate(),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if (tt.err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", tt.err, tt.wantErr)
			}
		})
	}
	if !errors.Is(ErrValidation, ErrValidation) {
		t.Fatal("sentinel error must support errors.Is")
	}
}
