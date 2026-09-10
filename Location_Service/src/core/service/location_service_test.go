package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"location/models"
	"location/src/core/repository"

	"github.com/google/uuid"
)

type currentRepoStub struct {
	location *models.CurrentLocation
	changes  []*models.SignalChange
	err      error
}

func (s *currentRepoStub) SaveCurrentLocation(
	context.Context,
	*models.RecordPositionInput,
) (*models.CurrentLocation, error) {
	return s.location, s.err
}

func (s *currentRepoStub) GetCurrentLocation(
	context.Context,
	*models.GetCurrentLocationInput,
) (*models.GetCurrentLocationResult, error) {
	return &models.GetCurrentLocationResult{Location: s.location}, s.err
}

func (s *currentRepoStub) GetCurrentLocations(
	context.Context,
	*models.GetCurrentLocationsInput,
) (*models.GetCurrentLocationsResult, error) {
	return nil, s.err
}

func (s *currentRepoStub) FindNearbyBrigades(
	context.Context,
	*models.FindNearbyBrigadesInput,
) (*models.FindNearbyBrigadesResult, error) {
	return nil, s.err
}

func (s *currentRepoStub) DetectLostSignals(
	context.Context,
	*models.DetectLostSignalsInput,
) (*models.DetectLostSignalsResult, error) {
	return &models.DetectLostSignalsResult{Changes: s.changes}, s.err
}

type sinkStub struct{ positions []*models.Position }

func (s *sinkStub) Add(position *models.Position) error {
	s.positions = append(s.positions, position)
	return nil
}

type failingSinkStub struct{ err error }

func (s failingSinkStub) Add(*models.Position) error { return s.err }

func TestRecordPositionBuffersOnlyNewPosition(t *testing.T) {
	position := validPosition()
	current := &currentRepoStub{location: &models.CurrentLocation{Position: position}}
	repo := repository.NewRepository(current, nil, nil)
	sink := &sinkStub{}
	svc := NewPositionServiceStructWithHistory(repo, sink)
	input := validRecordInput(position)
	result, err := svc.RecordPosition(context.Background(), input)
	if err != nil {
		t.Fatalf("record position: %v", err)
	}
	if result.Duplicate || len(sink.positions) != 1 {
		t.Fatalf("duplicate=%v buffered=%d", result.Duplicate, len(sink.positions))
	}
	current.location.Duplicate = true
	result, err = svc.RecordPosition(context.Background(), input)
	if err != nil {
		t.Fatalf("record duplicate: %v", err)
	}
	if !result.Duplicate || len(sink.positions) != 1 {
		t.Fatalf("duplicate=%v buffered=%d", result.Duplicate, len(sink.positions))
	}
}

func TestDetectLostSignalsReturnsRepositoryChanges(t *testing.T) {
	brigadeID := uuid.New()
	current := &currentRepoStub{
		changes: []*models.SignalChange{
			{BrigadeID: brigadeID, From: models.SignalStatusOnline, To: models.SignalStatusStale},
			{BrigadeID: brigadeID, From: models.SignalStatusStale, To: models.SignalStatusOffline},
		},
	}
	repo := repository.NewRepository(current, nil, nil)
	svc := NewPositionServiceStruct(repo)
	now := time.Now().UTC()
	result, err := svc.DetectLostSignals(
		context.Background(),
		&models.DetectLostSignalsInput{
			StaleBefore:   now.Add(-time.Minute),
			OfflineBefore: now.Add(-2 * time.Minute),
			Limit:         10,
		},
	)
	if err != nil {
		t.Fatalf("detect signals: %v", err)
	}
	if len(result.Changes) != 2 {
		t.Fatalf("changes = %#v", result.Changes)
	}
}

func TestRecordPositionHistoryFailureIsBestEffort(t *testing.T) {
	position := validPosition()
	repo := repository.NewRepository(
		&currentRepoStub{location: &models.CurrentLocation{Position: position}},
		nil,
		nil,
	)
	result, err := NewPositionServiceStructWithHistory(
		repo,
		failingSinkStub{err: models.ErrPositionBufferFull},
	).RecordPosition(context.Background(), validRecordInput(position))
	if err != nil {
		t.Fatalf("record position: %v", err)
	}
	if result.Position != position {
		t.Fatal("position was not returned")
	}
}

func TestPositionServiceWrapsRepositoryErrors(t *testing.T) {
	repo := repository.NewRepository(
		&currentRepoStub{err: models.ErrDependencyUnavailable},
		nil,
		nil,
	)
	_, err := NewPositionServiceStruct(
		repo,
	).GetCurrentLocation(
		context.Background(),
		&models.GetCurrentLocationInput{
			SubjectType: models.SubjectTypeDevice,
			SubjectID:   "device",
		},
	)
	if !errors.Is(err, models.ErrDependencyUnavailable) {
		t.Fatalf("error = %v", err)
	}
}

func validPosition() *models.Position {
	return &models.Position{
		ID:             uuid.New(),
		EventID:        uuid.New(),
		DeviceID:       "device-1",
		VehicleID:      uuid.New(),
		BrigadeID:      uuid.New(),
		Sequence:       1,
		Latitude:       55.75,
		Longitude:      37.61,
		AccuracyMeters: 3,
		RecordedAt:     time.Now().UTC(),
		ReceivedAt:     time.Now().UTC(),
	}
}
func validRecordInput(position *models.Position) *models.RecordPositionInput {
	return &models.RecordPositionInput{
		EventID:        position.EventID,
		EventVersion:   1,
		OccurredAt:     position.RecordedAt,
		DeviceID:       position.DeviceID,
		VehicleID:      position.VehicleID,
		BrigadeID:      position.BrigadeID,
		Sequence:       position.Sequence,
		Latitude:       position.Latitude,
		Longitude:      position.Longitude,
		SpeedKMH:       position.SpeedKMH,
		Heading:        position.Heading,
		AccuracyMeters: position.AccuracyMeters,
	}
}
