package service

import (
	"analytics/models"
	"analytics/pkg/telemetry"
	"analytics/src/core/repository"
	"context"
	"go.uber.org/zap"
	"time"
)

type AnalyticsServiceStruct struct {
	events        repository.EventRepository
	overview      repository.OverviewRepository
	sla           repository.SLARepository
	breakdown     repository.BreakdownRepository
	daily         repository.DailyRepository
	assets        repository.AssetRepository
	latency       repository.OperationalLatencyRepository
	failures      repository.DispatchFailureRepository
	workload      repository.BrigadeWorkloadRepository
	workers       repository.ActiveWorkersRepository
	funnel        repository.AssignmentFunnelRepository
	effectiveness repository.DispatchEffectivenessRepository
	insights      repository.OperationalInsightsRepository
	health        repository.ProjectionHealthRepository
	operations    repository.DispatchOperationsRepository
	performance   repository.BrigadePerformanceRepository
	logger        *zap.Logger
}

func NewAnalyticsServiceStruct(repo *repository.Repository, logger *zap.Logger) *AnalyticsServiceStruct {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AnalyticsServiceStruct{
		events:        repo.EventRepository,
		overview:      repo.OverviewRepository,
		sla:           repo.SLARepository,
		breakdown:     repo.BreakdownRepository,
		daily:         repo.DailyRepository,
		assets:        repo.AssetRepository,
		latency:       repo.OperationalLatencyRepository,
		failures:      repo.DispatchFailureRepository,
		workload:      repo.BrigadeWorkloadRepository,
		workers:       repo.ActiveWorkersRepository,
		funnel:        repo.AssignmentFunnelRepository,
		effectiveness: repo.DispatchEffectivenessRepository,
		insights:      repo.OperationalInsightsRepository,
		health:        repo.ProjectionHealthRepository,
		operations:    repo.DispatchOperationsRepository,
		performance:   repo.BrigadePerformanceRepository,
		logger:        logger,
	}
}
func (s *AnalyticsServiceStruct) BrigadePerformance(c context.Context, f models.Filter) (models.BrigadePerformance, error) {
	start := time.Now()
	value, err := s.performance.BrigadePerformance(c, f)
	s.logQuery("brigade performance", start, err,
		zap.Uint64("completed", value.Completed),
		zap.Int("brigades", len(value.Brigades)),
	)
	return value, err
}
func (s *AnalyticsServiceStruct) DispatchOperations(c context.Context, f models.Filter, limit uint32) ([]models.DispatchOperationItem, error) {
	start := time.Now()
	value, err := s.operations.DispatchOperations(c, f, limit)
	s.logQuery("dispatch operations", start, err, zap.Int("items", len(value)))
	return value, err
}
func (s *AnalyticsServiceStruct) ProjectionHealth(c context.Context) (models.ProjectionHealth, error) {
	start := time.Now()
	value, err := s.health.ProjectionHealth(c)
	s.logQuery("projection health", start, err,
		zap.Uint64("total_events", value.TotalEvents),
		zap.Uint64("unknown_versions", value.UnknownVersionEvents),
	)
	return value, err
}
func (s *AnalyticsServiceStruct) OperationalInsights(c context.Context, f models.Filter) (models.OperationalInsights, error) {
	start := time.Now()
	value, err := s.insights.OperationalInsights(c, f)
	s.logQuery("operational insights", start, err,
		zap.Uint64("queue_size", value.QueueAge.ActiveUnassigned),
		zap.Uint64("routes", value.Routing.Routes),
	)
	return value, err
}
func (s *AnalyticsServiceStruct) DispatchEffectiveness(c context.Context, f models.Filter) (models.DispatchEffectiveness, error) {
	start := time.Now()
	v, err := s.effectiveness.DispatchEffectiveness(c, f)
	s.logQuery("dispatch effectiveness", start, err,
		zap.Uint64("automatic_requested", v.Automatic.Requested),
		zap.Uint64("automatic_assigned", v.Automatic.Assigned),
	)
	return v, err
}
func (s *AnalyticsServiceStruct) AssignmentFunnel(c context.Context, f models.Filter) (models.AssignmentFunnel, error) {
	start := time.Now()
	v, err := s.funnel.AssignmentFunnel(c, f)
	s.logQuery("assignment funnel", start, err, zap.Int("stages", len(v.Stages)))
	return v, err
}
func (s *AnalyticsServiceStruct) ActiveWorkers(c context.Context, f models.Filter) (models.ActiveWorkers, error) {
	start := time.Now()
	v, err := s.workers.ActiveWorkers(c, f)
	s.logQuery("active workers", start, err, zap.Uint64("active_members", v.ActiveMembers), zap.Uint64("available", v.Available))
	return v, err
}
func (s *AnalyticsServiceStruct) BrigadeWorkload(c context.Context, f models.Filter) (models.BrigadeWorkload, error) {
	start := time.Now()
	v, err := s.workload.BrigadeWorkload(c, f)
	s.logQuery("brigade workload", start, err, zap.Uint64("active", v.Active), zap.Int("brigades", len(v.Brigades)))
	return v, err
}
func (s *AnalyticsServiceStruct) DispatchFailures(c context.Context, f models.Filter) (models.DispatchFailureSummary, error) {
	start := time.Now()
	v, err := s.failures.DispatchFailures(c, f)
	s.logQuery("dispatch failures", start, err, zap.Uint64("requested", v.Requested), zap.Uint64("failed", v.Failed+v.Expired+v.Canceled))
	return v, err
}
func (s *AnalyticsServiceStruct) OperationalLatency(c context.Context, f models.Filter, groupBy string) (models.OperationalLatency, error) {
	start := time.Now()
	v, err := s.latency.OperationalLatency(c, f, groupBy)
	s.logQuery(
		"operational latency",
		start,
		err,
		zap.Uint64("assignment_samples", v.AssignmentTime.SampleCount),
		zap.Uint64("routing_samples", v.RoutingCalculationTime.SampleCount),
	)
	return v, err
}
func (s *AnalyticsServiceStruct) AssetSummary(c context.Context, f models.Filter, t, d *string) (models.AssetSummary, error) {
	start := time.Now()
	v, e := s.assets.AssetSummary(c, f, t, d)
	s.logQuery("asset summary", start, e, zap.Uint64("incidents", v.Incidents))
	return v, e
}
func (s *AnalyticsServiceStruct) Consume(c context.Context, e models.Event) error {
	start := time.Now()
	if e.Version == 0 {
		e.Version = 1
	}
	e.ProjectionEligible = e.Version == 1
	if !e.ProjectionEligible {
		telemetry.RecordUnknownEventVersion(c, e.Topic, e.Version)
		s.logger.Warn("unknown analytics event version stored without projection", zap.String("topic", e.Topic), zap.String("event_type", e.Type), zap.Uint32("event_version", e.Version))
	}
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
