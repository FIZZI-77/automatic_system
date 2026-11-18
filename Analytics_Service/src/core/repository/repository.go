package repository

import (
	"analytics/models"
	"context"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type EventRepository interface {
	// Store сохраняет исходное событие с измерениями и признаком допуска к проекции.
	Store(context.Context, models.Event) error
}
type OverviewRepository interface {
	// Overview возвращает сводку заявок и средние времена реакции и решения в секундах.
	Overview(context.Context, models.Filter) (models.Overview, error)
}
type SLARepository interface {
	// SLA возвращает счётчики SLA-событий и долю нарушений относительно числа событий выборки.
	SLA(context.Context, models.Filter) (models.SLA, error)
}
type BreakdownRepository interface {
	// Breakdown группирует создания заявок по измерению с лимитом, процентами и общим счётчиком.
	Breakdown(context.Context, models.Filter, string, int32) ([]models.Breakdown, uint64, error)
}
type DailyRepository interface {
	// Daily возвращает дневные счётчики заявок и нарушений SLA в порядке дат.
	Daily(context.Context, models.Filter) ([]models.Daily, error)
}
type AssetRepository interface {
	// AssetSummary возвращает счётчики событий объектов и разрезы типа и района с отдельными фильтрами.
	AssetSummary(context.Context, models.Filter, *string, *string) (models.AssetSummary, error)
}
type OperationalLatencyRepository interface {
	// OperationalLatency возвращает распределения времени назначения и расчёта маршрутов в секундах с группировкой.
	OperationalLatency(context.Context, models.Filter, string) (models.OperationalLatency, error)
}
type DispatchFailureRepository interface {
	// DispatchFailures возвращает счётчики неуспешных операций, частоту и разрезы причин.
	DispatchFailures(context.Context, models.Filter) (models.DispatchFailureSummary, error)
}
type BrigadeWorkloadRepository interface {
	// BrigadeWorkload возвращает нагрузку бригад, неназначенную очередь и показатели неравномерности.
	BrigadeWorkload(context.Context, models.Filter) (models.BrigadeWorkload, error)
}
type ActiveWorkersRepository interface {
	// ActiveWorkers возвращает снимок активных, доступных и находящихся на смене сотрудников с разрезами.
	ActiveWorkers(context.Context, models.Filter) (models.ActiveWorkers, error)
}
type AssignmentFunnelRepository interface {
	// AssignmentFunnel возвращает этапы назначения со счётчиками, конверсией и временем переходов.
	AssignmentFunnel(context.Context, models.Filter) (models.AssignmentFunnel, error)
}
type DispatchEffectivenessRepository interface {
	// DispatchEffectiveness сравнивает успешность и длительность ручных и автоматических назначений.
	DispatchEffectiveness(context.Context, models.Filter) (models.DispatchEffectiveness, error)
}
type OperationalInsightsRepository interface {
	// OperationalInsights объединяет время выезда, возраст очереди, показатели маршрутов и оценку мощности.
	OperationalInsights(context.Context, models.Filter) (models.OperationalInsights, error)
}
type ProjectionHealthRepository interface {
	// ProjectionHealth возвращает показатели версий, свежести, поступления событий и полноты проекции.
	ProjectionHealth(context.Context) (models.ProjectionHealth, error)
}
type DispatchOperationsRepository interface {
	// DispatchOperations возвращает последние обновлённые операции по фильтрам с ограничением количества.
	DispatchOperations(context.Context, models.Filter, uint32) ([]models.DispatchOperationItem, error)
}
type BrigadePerformanceRepository interface {
	// BrigadePerformance возвращает выполнение, SLA, повторы объектов и сменные показатели бригад.
	BrigadePerformance(context.Context, models.Filter) (models.BrigadePerformance, error)
}
type DepartmentPerformanceRepository interface {
	// DepartmentPerformance возвращает показатели ведомств и организации по заявкам, SLA и отзывам.
	DepartmentPerformance(context.Context, models.Filter) (models.DepartmentPerformanceReport, error)
}
type Repository struct {
	EventRepository
	OverviewRepository
	SLARepository
	BreakdownRepository
	DailyRepository
	AssetRepository
	OperationalLatencyRepository
	DispatchFailureRepository
	BrigadeWorkloadRepository
	ActiveWorkersRepository
	AssignmentFunnelRepository
	DispatchEffectivenessRepository
	OperationalInsightsRepository
	ProjectionHealthRepository
	DispatchOperationsRepository
	BrigadePerformanceRepository
	DepartmentPerformanceRepository
}

// NewRepository объединяет запись событий и все аналитические запросы
// на одном хранилище ClickHouse с соединением db.
func NewRepository(db driver.Conn) *Repository {
	analytics := NewAnalyticsRepoStruct(db)
	return &Repository{
		EventRepository:                 analytics,
		OverviewRepository:              analytics,
		SLARepository:                   analytics,
		BreakdownRepository:             analytics,
		DailyRepository:                 analytics,
		AssetRepository:                 analytics,
		OperationalLatencyRepository:    analytics,
		DispatchFailureRepository:       analytics,
		BrigadeWorkloadRepository:       analytics,
		ActiveWorkersRepository:         analytics,
		AssignmentFunnelRepository:      analytics,
		DispatchEffectivenessRepository: analytics,
		OperationalInsightsRepository:   analytics,
		ProjectionHealthRepository:      analytics,
		DispatchOperationsRepository:    analytics,
		BrigadePerformanceRepository:    analytics,
		DepartmentPerformanceRepository: analytics,
	}
}
