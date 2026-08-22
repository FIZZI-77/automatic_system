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
type Repository struct {
	EventRepository
	OverviewRepository
	SLARepository
	BreakdownRepository
	DailyRepository
	AssetRepository
}

func NewRepository(db driver.Conn) *Repository {
	analytics := NewAnalyticsRepoStruct(db)
	return &Repository{EventRepository: analytics, OverviewRepository: analytics, SLARepository: analytics, BreakdownRepository: analytics, DailyRepository: analytics, AssetRepository: analytics}
}
