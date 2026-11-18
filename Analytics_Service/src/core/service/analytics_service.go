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
	departments   repository.DepartmentPerformanceRepository
	logger        *zap.Logger
}

// NewAnalyticsServiceStruct создаёт сервис приёма событий и аналитических запросов.
// nil logger заменяет журналом без вывода.
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
		departments:   repo.DepartmentPerformanceRepository,
		logger:        logger,
	}
}

// DepartmentPerformance возвращает показатели ведомств и организации по заявкам,
// SLA и отзывам, журналируя длительность и результат запроса.
func (s *AnalyticsServiceStruct) DepartmentPerformance(c context.Context, f models.Filter) (models.DepartmentPerformanceReport, error) {
	start := time.Now()
	value, err := s.departments.DepartmentPerformance(c, f)
	s.logQuery("department performance", start, err, zap.Int("departments", len(value.Departments)))
	return value, err
}

// BrigadePerformance возвращает показатели выполнения заявок, SLA и использования
// смен бригадами, сохраняя ошибку хранилища.
func (s *AnalyticsServiceStruct) BrigadePerformance(c context.Context, f models.Filter) (models.BrigadePerformance, error) {
	start := time.Now()
	value, err := s.performance.BrigadePerformance(c, f)
	s.logQuery("brigade performance", start, err,
		zap.Uint64("completed", value.Completed),
		zap.Int("brigades", len(value.Brigades)),
	)
	return value, err
}

// DispatchOperations возвращает последние операции диспетчеризации по фильтрам
// с ограничением limit, журналируя результат запроса.
func (s *AnalyticsServiceStruct) DispatchOperations(c context.Context, f models.Filter, limit uint32) ([]models.DispatchOperationItem, error) {
	start := time.Now()
	value, err := s.operations.DispatchOperations(c, f, limit)
	s.logQuery("dispatch operations", start, err, zap.Int("items", len(value)))
	return value, err
}

// ProjectionHealth возвращает состояние событий и проекции: полноту, версии,
// свежесть и задержки поступления, включая разрез топиков.
func (s *AnalyticsServiceStruct) ProjectionHealth(c context.Context) (models.ProjectionHealth, error) {
	start := time.Now()
	value, err := s.health.ProjectionHealth(c)
	s.logQuery("projection health", start, err,
		zap.Uint64("total_events", value.TotalEvents),
		zap.Uint64("unknown_versions", value.UnknownVersionEvents),
	)
	return value, err
}

// OperationalInsights возвращает время выезда, возраст очереди, показатели маршрутов
// и расчёт потребности в бригадах по данным хранилища.
func (s *AnalyticsServiceStruct) OperationalInsights(c context.Context, f models.Filter) (models.OperationalInsights, error) {
	start := time.Now()
	value, err := s.insights.OperationalInsights(c, f)
	s.logQuery("operational insights", start, err,
		zap.Uint64("queue_size", value.QueueAge.ActiveUnassigned),
		zap.Uint64("routes", value.Routing.Routes),
	)
	return value, err
}

// DispatchEffectiveness возвращает успешность и длительность автоматических
// и ручных назначений по фильтрам.
func (s *AnalyticsServiceStruct) DispatchEffectiveness(c context.Context, f models.Filter) (models.DispatchEffectiveness, error) {
	start := time.Now()
	v, err := s.effectiveness.DispatchEffectiveness(c, f)
	s.logQuery("dispatch effectiveness", start, err,
		zap.Uint64("automatic_requested", v.Automatic.Requested),
		zap.Uint64("automatic_assigned", v.Automatic.Assigned),
	)
	return v, err
}

// AssignmentFunnel возвращает этапы назначения со счётчиками, конверсией
// и распределением времени переходов.
func (s *AnalyticsServiceStruct) AssignmentFunnel(c context.Context, f models.Filter) (models.AssignmentFunnel, error) {
	start := time.Now()
	v, err := s.funnel.AssignmentFunnel(c, f)
	s.logQuery("assignment funnel", start, err, zap.Int("stages", len(v.Stages)))
	return v, err
}

// ActiveWorkers возвращает число активных, доступных и находящихся на смене
// сотрудников с разрезами ведомств и бригад.
func (s *AnalyticsServiceStruct) ActiveWorkers(c context.Context, f models.Filter) (models.ActiveWorkers, error) {
	start := time.Now()
	v, err := s.workers.ActiveWorkers(c, f)
	s.logQuery("active workers", start, err, zap.Uint64("active_members", v.ActiveMembers), zap.Uint64("available", v.Available))
	return v, err
}

// BrigadeWorkload возвращает нагрузку бригад, неназначенную очередь
// и показатели неравномерности распределения активных задач.
func (s *AnalyticsServiceStruct) BrigadeWorkload(c context.Context, f models.Filter) (models.BrigadeWorkload, error) {
	start := time.Now()
	v, err := s.workload.BrigadeWorkload(c, f)
	s.logQuery("brigade workload", start, err, zap.Uint64("active", v.Active), zap.Int("brigades", len(v.Brigades)))
	return v, err
}

// DispatchFailures возвращает частоту и классификацию неуспешных операций
// диспетчеризации по фильтрам.
func (s *AnalyticsServiceStruct) DispatchFailures(c context.Context, f models.Filter) (models.DispatchFailureSummary, error) {
	start := time.Now()
	v, err := s.failures.DispatchFailures(c, f)
	s.logQuery("dispatch failures", start, err, zap.Uint64("requested", v.Requested), zap.Uint64("failed", v.Failed+v.Expired+v.Canceled))
	return v, err
}

// OperationalLatency возвращает распределения времени назначения и расчёта маршрута
// в секундах с необязательной группировкой groupBy.
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

// AssetSummary возвращает показатели событий объектов и разрезы по типу и району.
// t и d ограничивают соответствующие разрезы, не общие счётчики.
func (s *AnalyticsServiceStruct) AssetSummary(c context.Context, f models.Filter, t, d *string) (models.AssetSummary, error) {
	start := time.Now()
	v, e := s.assets.AssetSummary(c, f, t, d)
	s.logQuery("asset summary", start, e, zap.Uint64("incidents", v.Incidents))
	return v, e
}

// Consume сохраняет событие, считая отсутствующую версию равной 1 и разрешая
// проекцию только для версии 1. Неизвестную версию тоже сохраняет, регистрируя
// метрику и предупреждение; изменяет только локальную копию e.
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

// Overview возвращает сводку заявок с долей завершения и средним временем реакции
// и решения в секундах.
func (s *AnalyticsServiceStruct) Overview(c context.Context, f models.Filter) (models.Overview, error) {
	start := time.Now()
	v, err := s.overview.Overview(c, f)
	s.logQuery("ticket overview", start, err, zap.Uint64("created", v.Created))
	return v, err
}

// SLA возвращает счётчики предупреждений, нарушений и завершений по событиям SLA.
func (s *AnalyticsServiceStruct) SLA(c context.Context, f models.Filter) (models.SLA, error) {
	start := time.Now()
	v, err := s.sla.SLA(c, f)
	s.logQuery("SLA summary", start, err, zap.Uint64("breaches", v.ResponseBreaches+v.ResolutionBreaches))
	return v, err
}

// Breakdown возвращает распределение событий создания заявок по измерению d
// с лимитом l, процентами и общим количеством.
func (s *AnalyticsServiceStruct) Breakdown(c context.Context, f models.Filter, d string, l int32) ([]models.Breakdown, uint64, error) {
	start := time.Now()
	v, total, err := s.breakdown.Breakdown(c, f, d, l)
	s.logQuery("ticket breakdown", start, err, zap.String("dimension", d), zap.Int("items", len(v)))
	return v, total, err
}

// Daily возвращает дневные счётчики создания, завершения и отмены заявок и нарушений SLA.
func (s *AnalyticsServiceStruct) Daily(c context.Context, f models.Filter) ([]models.Daily, error) {
	start := time.Now()
	v, err := s.daily.Daily(c, f)
	s.logQuery("daily metrics", start, err, zap.Int("items", len(v)))
	return v, err
}

// logQuery добавляет длительность запроса и пишет Info при успехе либо Error с причиной сбоя.
func (s *AnalyticsServiceStruct) logQuery(name string, start time.Time, err error, fields ...zap.Field) {
	fields = append(fields, zap.Duration("duration", time.Since(start)))

	if err != nil {
		s.logger.Error(name+" failed", append(fields, zap.Error(err))...)
		return
	}

	s.logger.Info(name+" completed", fields...)
}
