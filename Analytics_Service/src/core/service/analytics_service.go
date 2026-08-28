package service

import (
	"analytics/models"
	"analytics/src/core/repository"
	"context"
	"go.uber.org/zap"
	"time"
)

type AnalyticsServiceStruct struct {
	events    repository.EventRepository
	overview  repository.OverviewRepository
	sla       repository.SLARepository
	breakdown repository.BreakdownRepository
	daily     repository.DailyRepository
	assets    repository.AssetRepository
	logger    *zap.Logger
}

func NewAnalyticsServiceStruct(repo *repository.Repository, logger *zap.Logger) *AnalyticsServiceStruct {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AnalyticsServiceStruct{
		events:    repo.EventRepository,
		overview:  repo.OverviewRepository,
		sla:       repo.SLARepository,
		breakdown: repo.BreakdownRepository,
		daily:     repo.DailyRepository,
		assets:    repo.AssetRepository,
		logger:    logger,
	}
}
func (s *AnalyticsServiceStruct) AssetSummary(c context.Context, f models.Filter, t, d *string) (models.AssetSummary, error) {
	start := time.Now()
	v, e := s.assets.AssetSummary(c, f, t, d)
	s.logQuery("asset summary", start, e, zap.Uint64("incidents", v.Incidents))
	return v, e
}
func (s *AnalyticsServiceStruct) Consume(c context.Context, e models.Event) error {
	start := time.Now()
	err := s.events.Store(c, e)
	if err != nil {
		s.logger.Error("store analytics event failed", zap.String("topic", e.Topic), zap.String("event_type", e.Type), zap.Error(err))
		return err
	}
	s.logger.Debug("analytics event stored", zap.String("topic", e.Topic), zap.Duration("duration", time.Since(start)))
	return nil
}
func (s *AnalyticsServiceStruct) Overview(c context.Context, f models.Filter) (models.Overview, error) {
	start := time.Now()
	v, err := s.overview.Overview(c, f)
	s.logQuery("ticket overview", start, err, zap.Uint64("created", v.Created))
	return v, err
}
func (s *AnalyticsServiceStruct) SLA(c context.Context, f models.Filter) (models.SLA, error) {
	start := time.Now()
	v, err := s.sla.SLA(c, f)
	s.logQuery("SLA summary", start, err, zap.Uint64("breaches", v.ResponseBreaches+v.ResolutionBreaches))
	return v, err
}
func (s *AnalyticsServiceStruct) Breakdown(c context.Context, f models.Filter, d string, l int32) ([]models.Breakdown, uint64, error) {
	start := time.Now()
	v, total, err := s.breakdown.Breakdown(c, f, d, l)
	s.logQuery("ticket breakdown", start, err, zap.String("dimension", d), zap.Int("items", len(v)))
	return v, total, err
}
func (s *AnalyticsServiceStruct) Daily(c context.Context, f models.Filter) ([]models.Daily, error) {
	start := time.Now()
	v, err := s.daily.Daily(c, f)
	s.logQuery("daily metrics", start, err, zap.Int("items", len(v)))
	return v, err
}
func (s *AnalyticsServiceStruct) logQuery(name string, start time.Time, err error, fields ...zap.Field) {
	fields = append(fields, zap.Duration("duration", time.Since(start)))
	if err != nil {
		s.logger.Error(name+" failed", append(fields, zap.Error(err))...)
		return
	}
	s.logger.Info(name+" completed", fields...)
}
