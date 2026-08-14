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
}
type Service struct{ AnalyticsService }

func NewService(repo *repository.Repository, logger *zap.Logger) *Service {
	return &Service{AnalyticsService: NewAnalyticsServiceStruct(repo, logger)}
}
