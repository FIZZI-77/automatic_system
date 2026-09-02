package service

import (
	"analytics/models"
	"analytics/src/core/repository"
	"context"
	"go.uber.org/zap"
)

type AnalyticsService interface {
	Consume(context.Context, models.Event) error
	Overview(context.Context, models.Filter) (models.Overview, error)
	SLA(context.Context, models.Filter) (models.SLA, error)
	Breakdown(context.Context, models.Filter, string, int32) ([]models.Breakdown, uint64, error)
	Daily(context.Context, models.Filter) ([]models.Daily, error)
	AssetSummary(context.Context, models.Filter, *string, *string) (models.AssetSummary, error)
	OperationalLatency(context.Context, models.Filter, string) (models.OperationalLatency, error)
	DispatchFailures(context.Context, models.Filter) (models.DispatchFailureSummary, error)
	BrigadeWorkload(context.Context, models.Filter) (models.BrigadeWorkload, error)
	ActiveWorkers(context.Context, models.Filter) (models.ActiveWorkers, error)
	AssignmentFunnel(context.Context, models.Filter) (models.AssignmentFunnel, error)
	DispatchEffectiveness(context.Context, models.Filter) (models.DispatchEffectiveness, error)
	OperationalInsights(context.Context, models.Filter) (models.OperationalInsights, error)
	ProjectionHealth(context.Context) (models.ProjectionHealth, error)
	DispatchOperations(context.Context, models.Filter, uint32) ([]models.DispatchOperationItem, error)
	BrigadePerformance(context.Context, models.Filter) (models.BrigadePerformance, error)
}
type Service struct{ AnalyticsService }

func NewService(repo *repository.Repository, logger *zap.Logger) *Service {
	return &Service{AnalyticsService: NewAnalyticsServiceStruct(repo, logger)}
}
