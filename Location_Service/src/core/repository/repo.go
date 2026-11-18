package repository

import (
	"context"

	"location/models"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type CurrentLocationRepo interface {
	// SaveCurrentLocation сохраняет новую позицию, распознаёт повтор EventID и отклоняет устаревший Sequence.
	SaveCurrentLocation(
		ctx context.Context,
		in *models.RecordPositionInput,
	) (*models.CurrentLocation, error)
	// GetCurrentLocation возвращает позицию бригады, автомобиля или устройства с текущим статусом сигнала.
	GetCurrentLocation(
		ctx context.Context,
		in *models.GetCurrentLocationInput,
	) (*models.GetCurrentLocationResult, error)
	// GetCurrentLocations возвращает карту позиций уникальных бригад и Missing с учётом AllowStale.
	GetCurrentLocations(
		ctx context.Context,
		in *models.GetCurrentLocationsInput,
	) (*models.GetCurrentLocationsResult, error)
	// FindNearbyBrigades возвращает позиции в радиусе в метрах по расстоянию с фильтрами ID и свежести.
	FindNearbyBrigades(
		ctx context.Context,
		in *models.FindNearbyBrigadesInput,
	) (*models.FindNearbyBrigadesResult, error)
	// DetectLostSignals обновляет STALE/OFFLINE, очищает индексы OFFLINE и возвращает фактические изменения.
	DetectLostSignals(
		ctx context.Context,
		in *models.DetectLostSignalsInput,
	) (*models.DetectLostSignalsResult, error)
}

type PositionHistoryRepo interface {
	// AppendPositionsBatch записывает пакет истории и возвращает число строк, заполняя нулевые ID точек.
	AppendPositionsBatch(ctx context.Context, positions []*models.Position) (int64, error)
	// ListPositionHistory возвращает страницу истории бригады за [From, To) и отдельный общий счётчик.
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
	// CreateGeoZone сохраняет зону из GeoJSON с географическими координатами SRID 4326.
	CreateGeoZone(
		ctx context.Context,
		in *models.CreateGeoZoneInput,
	) (*models.CreateGeoZoneResult, error)
	// UpdateGeoZone меняет заданные поля геозоны; nil поля сохраняют прежние значения.
	UpdateGeoZone(
		ctx context.Context,
		in *models.UpdateGeoZoneInput,
	) (*models.UpdateGeoZoneResult, error)
	// DeleteGeoZone деактивирует зону и возвращает её запись; отсутствие даёт ErrNotFound.
	DeleteGeoZone(
		ctx context.Context,
		in *models.DeleteGeoZoneInput,
	) (*models.DeleteGeoZoneResult, error)
	// ListGeoZones возвращает страницу зон по ведомству и активности с общим счётчиком.
	ListGeoZones(
		ctx context.Context,
		in *models.ListGeoZonesInput,
	) (*models.ListGeoZonesResult, error)
	// CheckPointInZones возвращает активные зоны, покрывающие точку, включая границу.
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

// NewRepository объединяет заданные хранилища текущих позиций, истории и геозон.
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

// NewRepositoryFromClients создаёт хранилища PostgreSQL и Redis со стандартными
// настройками свежести позиций. nil pools.Read заменяет на pools.Write.
func NewRepositoryFromClients(pools DBPools, redisClient redis.UniversalClient) *Repository {
	return NewRepositoryFromClientsWithConfig(pools, redisClient, CurrentLocationRepoConfig{})
}

// NewRepositoryFromClientsWithConfig создаёт хранилища PostgreSQL и Redis
// с заданными настройками текущих позиций. nil pools.Read заменяет на pools.Write.
func NewRepositoryFromClientsWithConfig(
	pools DBPools,
	redisClient redis.UniversalClient,
	currentLocationConfig CurrentLocationRepoConfig,
) *Repository {

	if pools.Read == nil {
		pools.Read = pools.Write
	}

	return &Repository{
		CurrentLocationRepo: NewCurrentLocationRepoWithConfig(redisClient, currentLocationConfig),
		PositionHistoryRepo: NewPositionHistoryRepo(pools.Write, pools.Read),
		GeoZoneRepo:         NewGeoZoneRepo(pools.Write, pools.Read),
	}
}
