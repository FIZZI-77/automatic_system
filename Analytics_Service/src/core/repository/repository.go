package repository

import (
	"analytics/models"
	"context"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type EventRepository interface {
	Store(context.Context, models.Event) error
}
type OverviewRepository interface {
	Overview(context.Context, models.Filter) (models.Overview, error)
}
type SLARepository interface {
	SLA(context.Context, models.Filter) (models.SLA, error)
}
type BreakdownRepository interface {
	Breakdown(context.Context, models.Filter, string, int32) ([]models.Breakdown, uint64, error)
}
type DailyRepository interface {
	Daily(context.Context, models.Filter) ([]models.Daily, error)
}
type AssetRepository interface {
	AssetSummary(context.Context, models.Filter, *string, *string) (models.AssetSummary, error)
}
type OperationalLatencyRepository interface {
	OperationalLatency(context.Context, models.Filter, string) (models.OperationalLatency, error)
}
type DispatchFailureRepository interface {
	DispatchFailures(context.Context, models.Filter) (models.DispatchFailureSummary, error)
}
type BrigadeWorkloadRepository interface {
	BrigadeWorkload(context.Context, models.Filter) (models.BrigadeWorkload, error)
}
type ActiveWorkersRepository interface {
	ActiveWorkers(context.Context, models.Filter) (models.ActiveWorkers, error)
}
type AssignmentFunnelRepository interface {
	AssignmentFunnel(context.Context, models.Filter) (models.AssignmentFunnel, error)
}
type DispatchEffectivenessRepository interface {
	DispatchEffectiveness(context.Context, models.Filter) (models.DispatchEffectiveness, error)
}
type OperationalInsightsRepository interface {
	OperationalInsights(context.Context, models.Filter) (models.OperationalInsights, error)
}
type ProjectionHealthRepository interface {
	ProjectionHealth(context.Context) (models.ProjectionHealth, error)
}
type DispatchOperationsRepository interface {
	DispatchOperations(context.Context, models.Filter, uint32) ([]models.DispatchOperationItem, error)
}
type BrigadePerformanceRepository interface {
	BrigadePerformance(context.Context, models.Filter) (models.BrigadePerformance, error)
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
}

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
	}
}
