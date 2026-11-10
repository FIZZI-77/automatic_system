package service

import (
	"analytics/models"
	"analytics/src/core/repository"
	"context"
	"go.uber.org/zap"
)

type AnalyticsService interface {
	// Consume сохраняет событие, допуская к проекции только версию 1; неизвестные версии тоже сохраняются.
	Consume(context.Context, models.Event) error
	// Overview возвращает сводку заявок с долей завершений и средними временами в секундах.
	Overview(context.Context, models.Filter) (models.Overview, error)
	// SLA возвращает показатели предупреждений, нарушений и завершений по событиям SLA.
	SLA(context.Context, models.Filter) (models.SLA, error)
	// Breakdown возвращает распределение созданий заявок по измерению, проценты и общий счётчик.
	Breakdown(context.Context, models.Filter, string, int32) ([]models.Breakdown, uint64, error)
	// Daily возвращает дневные счётчики создания, завершения, отмены заявок и нарушений SLA.
	Daily(context.Context, models.Filter) ([]models.Daily, error)
	// AssetSummary возвращает показатели событий объектов с отдельными разрезами типа и района.
	AssetSummary(context.Context, models.Filter, *string, *string) (models.AssetSummary, error)
	// OperationalLatency возвращает распределения времени назначения и расчёта маршрутов в секундах с группировкой.
	OperationalLatency(context.Context, models.Filter, string) (models.OperationalLatency, error)
	// DispatchFailures возвращает частоту неуспешных назначений и классификацию причин.
	DispatchFailures(context.Context, models.Filter) (models.DispatchFailureSummary, error)
	// BrigadeWorkload возвращает нагрузку бригад, очередь без назначения и показатели баланса.
	BrigadeWorkload(context.Context, models.Filter) (models.BrigadeWorkload, error)
	// ActiveWorkers возвращает снимок активных, доступных и находящихся на смене сотрудников.
	ActiveWorkers(context.Context, models.Filter) (models.ActiveWorkers, error)
	// AssignmentFunnel возвращает этапы назначения с конверсией и временем переходов.
	AssignmentFunnel(context.Context, models.Filter) (models.AssignmentFunnel, error)
	// DispatchEffectiveness возвращает успешность и время ручных и автоматических назначений.
	DispatchEffectiveness(context.Context, models.Filter) (models.DispatchEffectiveness, error)
	// OperationalInsights возвращает время выезда, возраст очереди, показатели маршрутов и оценку потребности в бригадах.
	OperationalInsights(context.Context, models.Filter) (models.OperationalInsights, error)
	// ProjectionHealth возвращает состояние событий и проекции: версии, свежесть, задержку и полноту.
	ProjectionHealth(context.Context) (models.ProjectionHealth, error)
	// DispatchOperations возвращает последние операции диспетчеризации по фильтрам с ограничением количества.
	DispatchOperations(context.Context, models.Filter, uint32) ([]models.DispatchOperationItem, error)
	// BrigadePerformance возвращает показатели выполнения, SLA и использования смен бригадами.
	BrigadePerformance(context.Context, models.Filter) (models.BrigadePerformance, error)
	// DepartmentPerformance возвращает показатели ведомств и организации по заявкам, SLA и отзывам.
	DepartmentPerformance(context.Context, models.Filter) (models.DepartmentPerformanceReport, error)
}
type Service struct{ AnalyticsService }

// NewService объединяет приём событий и аналитические операции.
// nil logger допускается и отключает вывод журнала.
func NewService(repo *repository.Repository, logger *zap.Logger) *Service {
	return &Service{AnalyticsService: NewAnalyticsServiceStruct(repo, logger)}
}
