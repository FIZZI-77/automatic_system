package service

import (
	"context"

	"location/models"
	"location/src/core/repository"

	"go.uber.org/zap"
)

type PositionService interface {
	// RecordPosition проверяет и сохраняет точку, возвращая признак повтора; новую точку передаёт приёмнику истории.
	RecordPosition(
		ctx context.Context,
		in *models.RecordPositionInput,
	) (*models.RecordPositionResult, error)
	// GetCurrentLocation возвращает последнюю позицию субъекта с актуальным состоянием сигнала.
	GetCurrentLocation(
		ctx context.Context,
		in *models.GetCurrentLocationInput,
	) (*models.GetCurrentLocationResult, error)
	// GetCurrentLocations возвращает карту позиций бригад и Missing с учётом AllowStale.
	GetCurrentLocations(
		ctx context.Context,
		in *models.GetCurrentLocationsInput,
	) (*models.GetCurrentLocationsResult, error)
	// ListPositionHistory возвращает страницу истории бригады за [From, To) и общий счётчик.
	ListPositionHistory(
		ctx context.Context,
		in *models.ListPositionHistoryInput,
	) (*models.ListPositionHistoryResult, error)
	// FindNearbyBrigades возвращает бригады в радиусе по расстоянию с учётом ID и свежести позиций.
	FindNearbyBrigades(
		ctx context.Context,
		in *models.FindNearbyBrigadesInput,
	) (*models.FindNearbyBrigadesResult, error)
	// DetectLostSignals переводит устаревшие сигналы в STALE/OFFLINE и возвращает изменения.
	DetectLostSignals(
		ctx context.Context,
		in *models.DetectLostSignalsInput,
	) (*models.DetectLostSignalsResult, error)
}

type GeoZoneService interface {
	// CreateGeoZone проверяет запрос и создаёт зону для admin, system_admin или dispatcher.
	CreateGeoZone(
		ctx context.Context,
		in *models.CreateGeoZoneInput,
	) (*models.CreateGeoZoneResult, error)
	// UpdateGeoZone проверяет запрос и меняет заданные поля для admin, system_admin или dispatcher.
	UpdateGeoZone(
		ctx context.Context,
		in *models.UpdateGeoZoneInput,
	) (*models.UpdateGeoZoneResult, error)
	// DeleteGeoZone деактивирует зону для admin, system_admin или dispatcher без удаления строки.
	DeleteGeoZone(
		ctx context.Context,
		in *models.DeleteGeoZoneInput,
	) (*models.DeleteGeoZoneResult, error)
	// ListGeoZones проверяет пагинацию и возвращает страницу зон с общим счётчиком.
	ListGeoZones(
		ctx context.Context,
		in *models.ListGeoZonesInput,
	) (*models.ListGeoZonesResult, error)
	// CheckPointInZones проверяет координаты и возвращает активные зоны, покрывающие точку, включая границы зон.
	CheckPointInZones(
		ctx context.Context,
		in *models.CheckPointInZonesInput,
	) (*models.CheckPointInZonesResult, error)
}

type Service struct {
	PositionService
	GeoZoneService
}

// NewService объединяет позиции и геозоны без передачи точек в историю и вывода журнала.
func NewService(repo *repository.Repository) *Service {
	return NewServiceWithPositionHistory(repo, nil)
}

// NewServiceWithPositionHistory объединяет позиции и геозоны с приёмником истории
// без вывода журнала. nil history отключает передачу точек в историю.
func NewServiceWithPositionHistory(
	repo *repository.Repository,
	history PositionHistorySink,
) *Service {
	return NewServiceWithLogger(repo, history, zap.NewNop())
}

// NewServiceWithLogger объединяет позиции и геозоны с общим журналом и приёмником истории.
// nil history отключает передачу точек, nil logger — вывод журнала.
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
