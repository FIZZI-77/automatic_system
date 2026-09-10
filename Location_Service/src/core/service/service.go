package service

import (
	"context"

	"location/models"
	"location/src/core/repository"

	"go.uber.org/zap"
)

type PositionService interface {
	RecordPosition(
		ctx context.Context,
		in *models.RecordPositionInput,
	) (*models.RecordPositionResult, error)
	GetCurrentLocation(
		ctx context.Context,
		in *models.GetCurrentLocationInput,
	) (*models.GetCurrentLocationResult, error)
	GetCurrentLocations(
		ctx context.Context,
		in *models.GetCurrentLocationsInput,
	) (*models.GetCurrentLocationsResult, error)
	ListPositionHistory(
		ctx context.Context,
		in *models.ListPositionHistoryInput,
	) (*models.ListPositionHistoryResult, error)
	FindNearbyBrigades(
		ctx context.Context,
		in *models.FindNearbyBrigadesInput,
	) (*models.FindNearbyBrigadesResult, error)
	DetectLostSignals(
		ctx context.Context,
		in *models.DetectLostSignalsInput,
	) (*models.DetectLostSignalsResult, error)
}

type GeoZoneService interface {
	CreateGeoZone(
		ctx context.Context,
		in *models.CreateGeoZoneInput,
	) (*models.CreateGeoZoneResult, error)
	UpdateGeoZone(
		ctx context.Context,
		in *models.UpdateGeoZoneInput,
	) (*models.UpdateGeoZoneResult, error)
	DeleteGeoZone(
		ctx context.Context,
		in *models.DeleteGeoZoneInput,
	) (*models.DeleteGeoZoneResult, error)
	ListGeoZones(
		ctx context.Context,
		in *models.ListGeoZonesInput,
	) (*models.ListGeoZonesResult, error)
	CheckPointInZones(
		ctx context.Context,
		in *models.CheckPointInZonesInput,
	) (*models.CheckPointInZonesResult, error)
}

type Service struct {
	PositionService
	GeoZoneService
}

func NewService(repo *repository.Repository) *Service {
	return NewServiceWithPositionHistory(repo, nil)
}

func NewServiceWithPositionHistory(
	repo *repository.Repository,
	history PositionHistorySink,
) *Service {
	return NewServiceWithLogger(repo, history, zap.NewNop())
}

func NewServiceWithLogger(
	repo *repository.Repository,
	history PositionHistorySink,
	logger *zap.Logger,
) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{
		PositionService: NewPositionServiceStructWithLogger(repo, history, logger),
		GeoZoneService:  NewGeoZoneServiceStructWithLogger(repo, logger),
	}
}
