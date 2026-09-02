package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"location/models"

	"github.com/google/uuid"
)

func TestLocationIntegration_CurrentLocationGeoAndSequence(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()
	ctx := context.Background()
	in := integrationPositionInput(1, 55.751244, 37.618423)
	result, err := app.service.RecordPosition(ctx, in)
	if err != nil {
		t.Fatalf("record position: %v", err)
	}
	if result.Duplicate {
		t.Fatal("first position marked duplicate")
	}
	duplicate, err := app.service.RecordPosition(ctx, in)
	if err != nil {
		t.Fatalf("record duplicate: %v", err)
	}
	if !duplicate.Duplicate {
		t.Fatal("duplicate event was not detected")
	}
	older := *in
	older.EventID = uuid.New()
	if _, err = app.service.RecordPosition(ctx, &older); !errors.Is(
		err,
		models.ErrOutOfOrderPosition,
	) {
		t.Fatalf("out-of-order error = %v", err)
	}
	current, err := app.service.GetCurrentLocation(
		ctx,
		&models.GetCurrentLocationInput{
			SubjectType: models.SubjectTypeDevice,
			SubjectID:   in.DeviceID,
		},
	)
	if err != nil {
		t.Fatalf("get by device: %v", err)
	}
	if current.Location.Position.BrigadeID != in.BrigadeID {
		t.Fatalf("brigade = %s", current.Location.Position.BrigadeID)
	}
	nearby, err := app.service.FindNearbyBrigades(
		ctx,
		&models.FindNearbyBrigadesInput{
			Latitude:     in.Latitude,
			Longitude:    in.Longitude,
			RadiusMeters: 100,
			OnlyFresh:    true,
			Limit:        10,
		},
	)
	if err != nil {
		t.Fatalf("find nearby: %v", err)
	}
	if len(nearby.Brigades) != 1 || nearby.Brigades[0].BrigadeID != in.BrigadeID {
		t.Fatalf("nearby = %#v", nearby.Brigades)
	}
}

func TestLocationIntegration_CopyHistoryAndQuery(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()
	ctx := context.Background()
	in := integrationPositionInput(1, 55.75, 37.61)
	now := time.Now().UTC().Truncate(time.Microsecond)
	positions := []*models.Position{
		positionFromInput(in, now.Add(-2*time.Second)),
		positionFromInput(
			integrationPositionInputFor(in, 2, 55.751, 37.612),
			now.Add(-time.Second),
		),
	}
	written, err := app.repo.AppendPositionsBatch(ctx, positions)
	if err != nil {
		t.Fatalf("copy positions: %v", err)
	}
	if written != 2 {
		t.Fatalf("written = %d", written)
	}
	history, err := app.service.ListPositionHistory(
		ctx,
		&models.ListPositionHistoryInput{
			BrigadeID: in.BrigadeID,
			From:      now.Add(-time.Hour),
			To:        now.Add(time.Hour),
			Order:     models.SortOrderAsc,
		},
	)
	if err != nil {
		t.Fatalf("list history: %v", err)
	}
	if history.Total != 2 || len(history.Positions) != 2 {
		t.Fatalf("total=%d positions=%d", history.Total, len(history.Positions))
	}
	if history.Positions[0].Sequence != 1 || history.Positions[1].Sequence != 2 {
		t.Fatalf("unexpected order")
	}
}

func TestLocationIntegration_GeoZonesAndSignalStream(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()
	ctx := context.Background()
	departmentID := uuid.New()
	created, err := app.service.CreateGeoZone(
		ctx,
		&models.CreateGeoZoneInput{
			DepartmentID: departmentID,
			Name:         "Moscow center",
			GeoJSON:      `{"type":"Polygon","coordinates":[[[37.5,55.7],[37.7,55.7],[37.7,55.8],[37.5,55.8],[37.5,55.7]]]}`,
			ActorRoles:   []string{"dispatcher"},
		},
	)
	if err != nil {
		t.Fatalf("create zone: %v", err)
	}
	inside, err := app.service.CheckPointInZones(
		ctx,
		&models.CheckPointInZonesInput{
			Latitude:     55.75,
			Longitude:    37.61,
			DepartmentID: &departmentID,
		},
	)
	if err != nil {
		t.Fatalf("check zone: %v", err)
	}
	if len(inside.Zones) != 1 || inside.Zones[0].ID != created.Zone.ID {
		t.Fatalf("zones = %#v", inside.Zones)
	}
	deleted, err := app.service.DeleteGeoZone(
		ctx,
		&models.DeleteGeoZoneInput{ID: created.Zone.ID, ActorRoles: []string{"admin"}},
	)
	if err != nil || deleted.Zone.Active {
		t.Fatalf("delete zone: active=%v err=%v", deleted.Zone.Active, err)
	}
	position := integrationPositionInput(1, 55.75, 37.61)
	if _, err = app.service.RecordPosition(ctx, position); err != nil {
		t.Fatalf("record position: %v", err)
	}
	now := time.Now().UTC()
	thresholds := &models.DetectLostSignalsInput{
		StaleBefore:   now.Add(20 * time.Second),
		OfflineBefore: now.Add(10 * time.Second),
		Limit:         10,
	}
	result, err := app.service.DetectLostSignals(ctx, thresholds)
	if err != nil {
		t.Fatalf("detect lost signal: %v", err)
	}
	if len(result.Changes) != 1 || result.Changes[0].To != models.SignalStatusOffline {
		t.Fatalf("changes = %#v", result.Changes)
	}
	events, err := app.redis.XRangeN(ctx, "locations:events", "-", "+", 10).Result()
	if err != nil {
		t.Fatalf("read signal stream: %v", err)
	}
	if len(events) != 2 || events[0].Values["brigade_id"] != position.BrigadeID.String() ||
		events[0].Values["event_type"] != "VehiclePositionUpdated" ||
		events[1].Values["event_type"] != "BrigadeSignalLost" {
		t.Fatalf("stream events = %#v", events)
	}
	if _, err = app.service.DetectLostSignals(ctx, thresholds); err != nil {
		t.Fatalf("repeat signal detection: %v", err)
	}
	events, err = app.redis.XRangeN(ctx, "locations:events", "-", "+", 10).Result()
	if err != nil || len(events) != 2 {
		t.Fatalf("repeated stream events = %#v, err=%v", events, err)
	}
}

func integrationPositionInput(
	sequence uint64,
	latitude, longitude float64,
) *models.RecordPositionInput {
	return &models.RecordPositionInput{
		EventID:        uuid.New(),
		EventVersion:   1,
		OccurredAt:     time.Now().UTC(),
		DeviceID:       "device-" + uuid.NewString(),
		VehicleID:      uuid.New(),
		BrigadeID:      uuid.New(),
		Sequence:       sequence,
		Latitude:       latitude,
		Longitude:      longitude,
		SpeedKMH:       30,
		Heading:        90,
		AccuracyMeters: 2,
	}
}

func integrationPositionInputFor(
	base *models.RecordPositionInput,
	sequence uint64,
	latitude, longitude float64,
) *models.RecordPositionInput {
	in := *base
	in.EventID = uuid.New()
	in.Sequence = sequence
	in.Latitude = latitude
	in.Longitude = longitude
	return &in
}

func positionFromInput(in *models.RecordPositionInput, at time.Time) *models.Position {
	return &models.Position{
		ID:             uuid.New(),
		EventID:        in.EventID,
		DeviceID:       in.DeviceID,
		VehicleID:      in.VehicleID,
		BrigadeID:      in.BrigadeID,
		Sequence:       in.Sequence,
		Latitude:       in.Latitude,
		Longitude:      in.Longitude,
		SpeedKMH:       in.SpeedKMH,
		Heading:        in.Heading,
		AccuracyMeters: in.AccuracyMeters,
		RecordedAt:     at,
		ReceivedAt:     at,
	}
}
