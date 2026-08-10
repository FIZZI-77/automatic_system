package repository

import (
	"context"

	"location/models"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type CurrentLocationRepo interface {
	SaveCurrentLocation(
		ctx context.Context,
		in *models.RecordPositionInput,
	) (*models.CurrentLocation, error)
	GetCurrentLocation(
		ctx context.Context,
		in *models.GetCurrentLocationInput,
	) (*models.GetCurrentLocationResult, error)
	GetCurrentLocations(
		ctx context.Context,
		in *models.GetCurrentLocationsInput,
	) (*models.GetCurrentLocationsResult, error)
	FindNearbyBrigades(
		ctx context.Context,
		in *models.FindNearbyBrigadesInput,
	) (*models.FindNearbyBrigadesResult, error)
	DetectLostSignals(
		ctx context.Context,
		in *models.DetectLostSignalsInput,
	) (*models.DetectLostSignalsResult, error)
}

type PositionHistoryRepo interface {
	AppendPositionsBatch(ctx context.Context, positions []*models.Position) (int64, error)
	ListPositionHistory(
		ctx context.Context,
		in *models.ListPositionHistoryInput,
	) (*models.ListPositionHistoryResult, error)
}

type DBPools struct {
	Write *pgxpool.Pool
	Read  *pgxpool.Pool
}

type GeoZoneRepo interface {
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

type Repository struct {
	CurrentLocationRepo
	PositionHistoryRepo
	GeoZoneRepo
}

func NewRepository(
	current CurrentLocationRepo,
	history PositionHistoryRepo,
	zones GeoZoneRepo,
) *Repository {
	return &Repository{
		CurrentLocationRepo: current,
		PositionHistoryRepo: history,
		GeoZoneRepo:         zones,
	}
}

func NewRepositoryFromClients(pools DBPools, redisClient redis.UniversalClient) *Repository {
	if pools.Read == nil {
		pools.Read = pools.Write
	}
	return &Repository{
		CurrentLocationRepo: NewCurrentLocationRepo(redisClient),
		PositionHistoryRepo: NewPositionHistoryRepo(pools.Write, pools.Read),
		GeoZoneRepo:         NewGeoZoneRepo(pools.Write, pools.Read),
	}
}
