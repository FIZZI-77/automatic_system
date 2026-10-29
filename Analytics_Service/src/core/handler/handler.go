package handler

import (
	"analytics/models"
	"analytics/src/core/service"
	"context"
	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"strings"
)

type Handler struct {
	analyticsv1.UnimplementedAnalyticsServiceServer
	s service.AnalyticsService
}

// New создаёт gRPC-обработчик аналитики с переданным сервисом.
func New(s service.AnalyticsService) *Handler {
	return &Handler{s: s}
}

// GetTicketOverview требует admin или dispatcher и возвращает счётчики заявок,
// долю завершения и средние сроки из сервиса; ошибки запроса скрывает за Internal.
func (h *Handler) GetTicketOverview(c context.Context, q *analyticsv1.GetTicketOverviewRequest) (*analyticsv1.GetTicketOverviewResponse, error) {

	if e := auth(c); e != nil {
		return nil, e
	}

	v, e := h.s.Overview(c, filter(q.GetFilter()))

	if e != nil {
		return nil, internal(e)
	}

	return &analyticsv1.GetTicketOverviewResponse{
		Created:              v.Created,
		Completed:            v.Completed,
		Canceled:             v.Canceled,
		Active:               v.Active,
		CompletionRate:       v.CompletionRate,
		AvgResponseSeconds:   v.AvgResponseSeconds,
		AvgResolutionSeconds: v.AvgResolutionSeconds,
	}, nil
}

// GetSLASummary требует admin или dispatcher и возвращает сводку предупреждений,
// нарушений и завершений SLA по преобразованному фильтру.
func (h *Handler) GetSLASummary(c context.Context, q *analyticsv1.GetSLASummaryRequest) (*analyticsv1.GetSLASummaryResponse, error) {

	if e := auth(c); e != nil {
		return nil, e
	}

	v, e := h.s.SLA(c, filter(q.GetFilter()))

	if e != nil {
		return nil, internal(e)
	}

	return &analyticsv1.GetSLASummaryResponse{
		ResponseWarnings:   v.ResponseWarnings,
		ResponseBreaches:   v.ResponseBreaches,
		ResolutionWarnings: v.ResolutionWarnings,
		ResolutionBreaches: v.ResolutionBreaches,
		Completed:          v.Completed,
		BreachRate:         v.BreachRate,
	}, nil
}

// ListTicketBreakdown требует admin или dispatcher, преобразует измерение
// группировки и возвращает группы с числом, долей и общим счётчиком.
// Любую ошибку сервиса возвращает как InvalidArgument с её текстом.
func (h *Handler) ListTicketBreakdown(c context.Context, q *analyticsv1.ListTicketBreakdownRequest) (*analyticsv1.ListTicketBreakdownResponse, error) {

	if e := auth(c); e != nil {
		return nil, e
	}

	d := strings.TrimPrefix(q.GetDimension().String(), "BREAKDOWN_DIMENSION_")
	items, total, e := h.s.Breakdown(c, filter(q.GetFilter()), d, q.GetLimit())

	if e != nil {
		return nil, status.Error(codes.InvalidArgument, e.Error())
	}

	out := make([]*analyticsv1.TicketBreakdown, 0, len(items))
	for _, v := range items {
		out = append(out, &analyticsv1.TicketBreakdown{
			Key:     v.Key,
			Count:   v.Count,
			Percent: v.Percent,
		})
	}

	return &analyticsv1.ListTicketBreakdownResponse{Items: out, Total: total}, nil
}

// ListDailyTicketMetrics требует admin или dispatcher и преобразует дневные
// счётчики заявок и нарушений SLA из сервиса в protobuf с датами.
func (h *Handler) ListDailyTicketMetrics(c context.Context, q *analyticsv1.ListDailyTicketMetricsRequest) (*analyticsv1.ListDailyTicketMetricsResponse, error) {

	if e := auth(c); e != nil {
		return nil, e
	}

	items, e := h.s.Daily(c, filter(q.GetFilter()))

	if e != nil {
		return nil, internal(e)
	}

	out := make([]*analyticsv1.DailyTicketMetric, 0, len(items))
	for _, v := range items {
		out = append(out, &analyticsv1.DailyTicketMetric{
			Day:         timestamppb.New(v.Day),
			Created:     v.Created,
			Completed:   v.Completed,
			Canceled:    v.Canceled,
			SlaBreaches: v.SLABreaches,
		})
	}
	return &analyticsv1.ListDailyTicketMetricsResponse{Items: out}, nil
}

// filter преобразует временные границы и сохраняет необязательные условия
// аналитики без проверки форматов; nil даёт пустой доменный фильтр.
func filter(v *analyticsv1.AnalyticsFilter) models.Filter {

	if v == nil {
		return models.Filter{}
	}

	f := models.Filter{
		DepartmentID:   v.DepartmentId,
		CategoryID:     v.CategoryId,
		Priority:       v.Priority,
		BrigadeID:      v.BrigadeId,
		AssignmentMode: v.AssignmentMode,
		FailureCode:    v.FailureCode,
		Success:        v.Success,
	}

	if v.From != nil {
		x := v.From.AsTime()
		f.From = &x
	}

	if v.To != nil {
		x := v.To.AsTime()
		f.To = &x
	}

	return f
}

// auth разрешает admin или dispatcher из x-actor-roles, игнорируя регистр
// и крайние пробелы; иначе возвращает PermissionDenied.
func auth(c context.Context) error {
	m, _ := metadata.FromIncomingContext(c)
	for _, r := range strings.Split(strings.Join(m.Get("x-actor-roles"), ","), ",") {

		if x := strings.ToLower(strings.TrimSpace(r)); x == "admin" || x == "dispatcher" {
			return nil
		}

	}
	return status.Error(codes.PermissionDenied, "admin or dispatcher role required")
}

// internal скрывает переданную ошибку за общим gRPC Internal для запроса аналитики.
func internal(error) error {
	return status.Error(codes.Internal, "analytics query failed")
}

// GetAssetSummary требует admin или dispatcher и возвращает сводку объектов,
// инцидентов, ремонтов и осмотров с группами по типу и району.
func (h *Handler) GetAssetSummary(c context.Context, q *analyticsv1.GetAssetSummaryRequest) (*analyticsv1.GetAssetSummaryResponse, error) {

	if e := auth(c); e != nil {
		return nil, e
	}

	v, e := h.s.AssetSummary(c, filter(q.Filter), q.AssetType, q.District)

	if e != nil {
		return nil, internal(e)
	}

	out := &analyticsv1.GetAssetSummaryResponse{
		AssetsCreated:       v.Created,
		Incidents:           v.Incidents,
		RepeatedIncidents:   v.Repeated,
		Repairs:             v.Repairs,
		Inspections:         v.Inspections,
		CriticalRiskUpdates: v.Critical,
	}
	for _, x := range v.ByType {
		out.ByType = append(out.ByType, assetBreakdown(x))
	}

	for _, x := range v.ByDistrict {
		out.ByDistrict = append(out.ByDistrict, assetBreakdown(x))
	}

	return out, nil
}

// GetOperationalLatency требует admin или dispatcher, преобразует измерение
// группировки и возвращает распределения времени назначения и расчёта маршрута.
func (h *Handler) GetOperationalLatency(c context.Context, q *analyticsv1.GetOperationalLatencyRequest) (*analyticsv1.GetOperationalLatencyResponse, error) {

	if err := auth(c); err != nil {
		return nil, err
	}

	groupBy := strings.TrimPrefix(q.GetGroupBy().String(), "OPERATIONAL_LATENCY_DIMENSION_")
	value, err := h.s.OperationalLatency(c, filter(q.GetFilter()), groupBy)

	if err != nil {
		return nil, internal(err)
	}

	groups := make([]*analyticsv1.OperationalLatencyGroup, 0, len(value.Groups))
	for _, group := range value.Groups {
		groups = append(groups, &analyticsv1.OperationalLatencyGroup{
			Dimension:              group.Dimension,
			Key:                    group.Key,
			AssignmentTime:         latencyDistribution(group.AssignmentTime),
			RoutingCalculationTime: latencyDistribution(group.RoutingCalculationTime),
		})
	}

	return &analyticsv1.GetOperationalLatencyResponse{
		AssignmentTime:         latencyDistribution(value.AssignmentTime),
		RoutingCalculationTime: latencyDistribution(value.RoutingCalculationTime),
		Groups:                 groups,
	}, nil
}

// GetDispatchFailureSummary требует admin или dispatcher и преобразует сводку
// отказов назначения с группировками по этапам, кодам, причинам, ведомствам и категориям.
func (h *Handler) GetDispatchFailureSummary(c context.Context, q *analyticsv1.GetDispatchFailureSummaryRequest) (*analyticsv1.GetDispatchFailureSummaryResponse, error) {

	if err := auth(c); err != nil {
		return nil, err
	}

	value, err := h.s.DispatchFailures(c, filter(q.GetFilter()))

	if err != nil {
		return nil, internal(err)
	}

	return &analyticsv1.GetDispatchFailureSummaryResponse{
		Requested: value.Requested, Failed: value.Failed, Expired: value.Expired,
		Canceled: value.Canceled, FailureRate: value.FailureRate,
		ByStage:             dispatchFailureBreakdowns(value.ByStage),
		ByCode:              dispatchFailureBreakdowns(value.ByCode),
		BusinessReasons:     dispatchFailureReasons(value.BusinessReasons),
		ReasonsByDepartment: dispatchFailureReasonDimensions(value.ReasonsByDepartment),
		ReasonsByCategory:   dispatchFailureReasonDimensions(value.ReasonsByCategory),
	}, nil
}

// GetBrigadeWorkload требует admin или dispatcher и возвращает нагрузку по бригадам,
// очередь без назначения и показатели распределения нагрузки из сервиса.
func (h *Handler) GetBrigadeWorkload(c context.Context, q *analyticsv1.GetBrigadeWorkloadRequest) (*analyticsv1.GetBrigadeWorkloadResponse, error) {

	if err := auth(c); err != nil {
		return nil, err
	}

	value, err := h.s.BrigadeWorkload(c, filter(q.GetFilter()))

	if err != nil {
		return nil, internal(err)
	}

	brigades := make([]*analyticsv1.BrigadeWorkloadItem, 0, len(value.Brigades))
	for _, item := range value.Brigades {
		brigades = append(brigades, &analyticsv1.BrigadeWorkloadItem{
			BrigadeId: item.BrigadeID, Incoming: item.Incoming, Assigned: item.Assigned,
			Completed: item.Completed, Active: item.Active,
		})
	}
	return &analyticsv1.GetBrigadeWorkloadResponse{
		Incoming: value.Incoming, Assigned: value.Assigned, Completed: value.Completed,
		Active: value.Active, UnassignedBacklog: value.UnassignedBacklog, Brigades: brigades,
		BrigadeCount: value.BrigadeCount, MaxActive: value.MaxActive,
		AverageActive: value.AverageActive, StandardDeviation: value.StandardDeviation,
		CoefficientOfVariation: value.CoefficientOfVariation, Gini: value.Gini,
	}, nil
}

// GetActiveWorkers требует admin или dispatcher и возвращает численность активных,
// доступных и работающих в смене участников с группами по ведомствам и бригадам.
func (h *Handler) GetActiveWorkers(c context.Context, q *analyticsv1.GetActiveWorkersRequest) (*analyticsv1.GetActiveWorkersResponse, error) {

	if err := auth(c); err != nil {
		return nil, err
	}

	value, err := h.s.ActiveWorkers(c, filter(q.GetFilter()))

	if err != nil {
		return nil, internal(err)
	}

	return &analyticsv1.GetActiveWorkersResponse{
		ActiveMembers: value.ActiveMembers,
		Available:     value.Available,
		OnShift:       value.OnShift,
		ByDepartment:  activeWorkerGroups(value.ByDepartment),
		ByBrigade:     activeWorkerGroups(value.ByBrigade),
	}, nil
}

// GetAssignmentFunnel требует admin или dispatcher и возвращает этапы назначения
// с числом операций, конверсией и распределением времени перехода из сервиса.
func (h *Handler) GetAssignmentFunnel(c context.Context, q *analyticsv1.GetAssignmentFunnelRequest) (*analyticsv1.GetAssignmentFunnelResponse, error) {

	if err := auth(c); err != nil {
		return nil, err
	}

	value, err := h.s.AssignmentFunnel(c, filter(q.GetFilter()))

	if err != nil {
		return nil, internal(err)
	}

	stages := make([]*analyticsv1.AssignmentFunnelStage, 0, len(value.Stages))
	for _, stage := range value.Stages {
		stages = append(stages, &analyticsv1.AssignmentFunnelStage{
			Stage:                  stage.Stage,
			Count:                  stage.Count,
			ConversionFromPrevious: stage.ConversionFromPrevious,
			TransitionTime:         latencyDistribution(stage.TransitionTime),
		})
	}
	return &analyticsv1.GetAssignmentFunnelResponse{Stages: stages}, nil
}

// GetDispatchEffectiveness требует admin или dispatcher и возвращает показатели
// ручного и автоматического назначения и признак доступности данных переназначений.
func (h *Handler) GetDispatchEffectiveness(c context.Context, q *analyticsv1.GetDispatchEffectivenessRequest) (*analyticsv1.GetDispatchEffectivenessResponse, error) {

	if err := auth(c); err != nil {
		return nil, err
	}

	value, err := h.s.DispatchEffectiveness(c, filter(q.GetFilter()))

	if err != nil {
		return nil, internal(err)
	}

	return &analyticsv1.GetDispatchEffectivenessResponse{
		Automatic:                   dispatchModeEffectiveness(value.Automatic),
		Manual:                      dispatchModeEffectiveness(value.Manual),
		ManualReassignmentAvailable: value.ManualReassignmentAvailable,
	}, nil
}

// GetOperationalInsights требует admin или dispatcher и преобразует результаты
// анализа выезда, возраста очереди, эффективности маршрутов, ошибок ETA
// и прогноза потребности в бригадах; формулы и метрики получает из сервиса.
func (h *Handler) GetOperationalInsights(c context.Context, q *analyticsv1.GetOperationalInsightsRequest) (*analyticsv1.GetOperationalInsightsResponse, error) {

	if err := auth(c); err != nil {
		return nil, err
	}

	value, err := h.s.OperationalInsights(c, filter(q.GetFilter()))

	if err != nil {
		return nil, internal(err)
	}

	buckets := make([]*analyticsv1.QueueAgeBucket, 0, len(value.QueueAge.Buckets))

	for _, bucket := range value.QueueAge.Buckets {
		buckets = append(buckets, &analyticsv1.QueueAgeBucket{Range: bucket.Range, Count: bucket.Count})
	}

	return &analyticsv1.GetOperationalInsightsResponse{
		DepartureTime: latencyDistribution(value.DepartureTime),
		QueueAge: &analyticsv1.QueueAgeSummary{
			ActiveUnassigned: value.QueueAge.ActiveUnassigned,
			Age:              latencyDistribution(value.QueueAge.Age),
			Buckets:          buckets,
		},
		Routing: &analyticsv1.RoutingEfficiency{
			Routes: value.Routing.Routes, Recalculations: value.Routing.Recalculations,
			Cancellations:                value.Routing.Cancellations,
			UnreachableCandidateRate:     value.Routing.UnreachableCandidateRate,
			AverageDistanceKm:            value.Routing.AverageDistanceKM,
			KilometersPerCompletedTicket: value.Routing.KilometersPerCompletedTicket,
			EtaSampleCount:               value.Routing.ETASampleCount,
			EtaMeanAbsoluteErrorSeconds:  value.Routing.ETAMeanAbsoluteErrorSeconds,
			EtaBiasSeconds:               value.Routing.ETABiasSeconds,
			EtaP95AbsoluteErrorSeconds:   value.Routing.ETAP95AbsoluteErrorSeconds,
			EtaWithinFiveMinutesRate:     value.Routing.ETAWithinFiveMinutesRate,
		},
		CapacityForecast: &analyticsv1.CapacityForecast{
			ObservedDays:         value.CapacityForecast.ObservedDays,
			AverageDailyIncoming: value.CapacityForecast.AverageDailyIncoming,
			ForecastNextDay:      value.CapacityForecast.ForecastNextDay,
			PeakHourlyIncoming:   value.CapacityForecast.PeakHourlyIncoming,
			RequiredBrigades:     value.CapacityForecast.RequiredBrigades,
			Formula:              value.CapacityForecast.Formula,
		},
	}, nil
}

// GetProjectionHealth требует admin или dispatcher и возвращает состояние
// проекций событий, свежесть и задержку загрузки в целом и по топикам.
func (h *Handler) GetProjectionHealth(c context.Context, _ *analyticsv1.GetProjectionHealthRequest) (*analyticsv1.GetProjectionHealthResponse, error) {

	if err := auth(c); err != nil {
		return nil, err
	}

	value, err := h.s.ProjectionHealth(c)

	if err != nil {
		return nil, internal(err)
	}

	topics := make([]*analyticsv1.ProjectionTopicHealth, 0, len(value.Topics))

	for _, topic := range value.Topics {
		topics = append(topics, projectionTopicHealth(topic))
	}

	return &analyticsv1.GetProjectionHealthResponse{
		TotalEvents: value.TotalEvents, UnknownVersionEvents: value.UnknownVersionEvents,
		ProjectionEligibleRate: value.ProjectionEligibleRate,
		ProjectedEvents:        value.ProjectedEvents, MissingProjectionEvents: value.MissingProjectionEvents,
		ProjectionErrorRate: value.ProjectionErrorRate,
		LastOccurredAt:      timestamppb.New(value.LastOccurredAt), LastIngestedAt: timestamppb.New(value.LastIngestedAt),
		FreshnessSeconds: value.FreshnessSeconds, IngestionP95Seconds: value.IngestionP95Seconds,
		Topics: topics,
	}, nil
}

// projectionTopicHealth преобразует метрики проекции топика и даты последних
// событий и загрузки в protobuf без пересчёта показателей.
func projectionTopicHealth(value models.ProjectionTopicHealth) *analyticsv1.ProjectionTopicHealth {
	return &analyticsv1.ProjectionTopicHealth{
		Topic: value.Topic, TotalEvents: value.TotalEvents, UnknownVersionEvents: value.UnknownVersionEvents,
		ProjectionEligibleRate: value.ProjectionEligibleRate,
		LastOccurredAt:         timestamppb.New(value.LastOccurredAt), LastIngestedAt: timestamppb.New(value.LastIngestedAt),
		FreshnessSeconds: value.FreshnessSeconds, IngestionP95Seconds: value.IngestionP95Seconds,
	}
}

// ListDispatchOperations требует admin или dispatcher и возвращает операции
// назначения по фильтру и лимиту с кодами отказа, trace ID и временными метками.
func (h *Handler) ListDispatchOperations(c context.Context, q *analyticsv1.ListDispatchOperationsRequest) (*analyticsv1.ListDispatchOperationsResponse, error) {

	if err := auth(c); err != nil {
		return nil, err
	}

	values, err := h.s.DispatchOperations(c, filter(q.GetFilter()), q.GetLimit())

	if err != nil {
		return nil, internal(err)
	}

	items := make([]*analyticsv1.DispatchOperationItem, 0, len(values))

	for _, value := range values {
		items = append(items, &analyticsv1.DispatchOperationItem{
			OperationId: value.OperationID, TicketId: value.TicketID, DepartmentId: value.DepartmentID,
			CategoryId: value.CategoryID, BrigadeId: value.BrigadeID, AssignmentMode: value.AssignmentMode,
			Status: value.Status, FailureCode: value.FailureCode, FailureStage: value.FailureStage,
			TraceId: value.TraceID, RequestedAt: timestamppb.New(value.RequestedAt), UpdatedAt: timestamppb.New(value.UpdatedAt),
		})
	}

	return &analyticsv1.ListDispatchOperationsResponse{Items: items}, nil
}

// GetBrigadePerformance требует admin или dispatcher и преобразует показатели
// выполнения, SLA, смен и загрузки в общую сводку и данные отдельных бригад.
func (h *Handler) GetBrigadePerformance(c context.Context, q *analyticsv1.GetBrigadePerformanceRequest) (*analyticsv1.GetBrigadePerformanceResponse, error) {

	if err := auth(c); err != nil {
		return nil, err
	}

	value, err := h.s.BrigadePerformance(c, filter(q.GetFilter()))

	if err != nil {
		return nil, internal(err)
	}

	brigades := make([]*analyticsv1.BrigadePerformanceItem, 0, len(value.Brigades))

	for _, brigade := range value.Brigades {
		brigades = append(brigades, &analyticsv1.BrigadePerformanceItem{
			BrigadeId: brigade.BrigadeID, Completed: brigade.Completed,
			ExecutionTime: latencyDistribution(brigade.ExecutionTime), SlaBreaches: brigade.SLABreaches,
			SlaBreachRate: brigade.SLABreachRate, RepeatedAssetTickets: brigade.RepeatedAssetTickets,
			ShiftCount: brigade.ShiftCount, ShiftHours: brigade.ShiftHours,
			CompletedPerShift: brigade.CompletedPerShift, UtilizationRate: brigade.UtilizationRate,
			BusyHours: brigade.BusyHours, AverageParallelTasks: brigade.AverageParallelTasks,
		})

	}
	return &analyticsv1.GetBrigadePerformanceResponse{
		Completed: value.Completed, ExecutionTime: latencyDistribution(value.ExecutionTime),
		SlaBreaches: value.SLABreaches, SlaBreachRate: value.SLABreachRate,
		RepeatedAssetTickets: value.RepeatedAssetTickets, ShiftMetricsAvailable: value.ShiftMetricsAvailable,
		ShiftCount: value.ShiftCount, ShiftHours: value.ShiftHours,
		CompletedPerShift: value.CompletedPerShift, UtilizationRate: value.UtilizationRate,
		BusyHours: value.BusyHours, AverageParallelTasks: value.AverageParallelTasks,
		Brigades: brigades,
	}, nil
}

// GetDepartmentPerformance требует именно admin из метаданных, игнорируя регистр
// и пробелы, и возвращает показатели ведомств и организации. Отказ даёт PermissionDenied.
func (h *Handler) GetDepartmentPerformance(c context.Context, q *analyticsv1.GetDepartmentPerformanceRequest) (*analyticsv1.GetDepartmentPerformanceResponse, error) {
	roles, _ := metadata.FromIncomingContext(c)
	admin := false
	for _, role := range strings.Split(strings.Join(roles.Get("x-actor-roles"), ","), ",") {

		if strings.EqualFold(strings.TrimSpace(role), "admin") {
			admin = true
			break
		}

	}

	if !admin {
		return nil, status.Error(codes.PermissionDenied, "admin role required")
	}

	report, err := h.s.DepartmentPerformance(c, filter(q.GetFilter()))

	if err != nil {
		return nil, internal(err)
	}

	departments := make([]*analyticsv1.DepartmentPerformance, 0, len(report.Departments))
	for _, value := range report.Departments {
		departments = append(departments, departmentPerformance(value))
	}

	return &analyticsv1.GetDepartmentPerformanceResponse{
		Departments:  departments,
		Organization: departmentPerformance(report.Organization),
	}, nil
}

// departmentPerformance переносит показатели заявок, сроков, SLA и обратной связи
// ведомства в protobuf без самостоятельного расчёта долей и средних.
func departmentPerformance(value models.DepartmentPerformance) *analyticsv1.DepartmentPerformance {
	return &analyticsv1.DepartmentPerformance{
		DepartmentId: value.DepartmentID, Created: value.Created, Completed: value.Completed,
		Canceled: value.Canceled, Active: value.Active, CompletionRate: value.CompletionRate,
		AverageResponseSeconds: value.AverageResponseSeconds, AverageResolutionSeconds: value.AverageResolutionSeconds,
		ResponseSampleCount: value.ResponseSampleCount, ResolutionSampleCount: value.ResolutionSampleCount,
		ResponseSlaSampleCount: value.ResponseSLASampleCount, ResponseSlaBreaches: value.ResponseSLABreaches,
		AverageResponseSlaDeviationSeconds: value.AverageResponseSLADeviationSeconds,
		ResolutionSlaSampleCount:           value.ResolutionSLASampleCount, ResolutionSlaBreaches: value.ResolutionSLABreaches,
		AverageResolutionSlaDeviationSeconds: value.AverageResolutionSLADeviationSeconds,
		FeedbackCount:                        value.FeedbackCount, AverageRating: value.AverageRating,
		PositiveRatingRate: value.PositiveRatingRate, ResolvedFeedbackRate: value.ResolvedFeedbackRate,
		FeedbackResponseRate: value.FeedbackResponseRate,
	}
}

// activeWorkerGroups преобразует группы численности участников в protobuf
// с сохранением порядка; пустой вход даёт пустой ненулевой срез.
func activeWorkerGroups(values []models.ActiveWorkerGroup) []*analyticsv1.ActiveWorkerGroup {
	result := make([]*analyticsv1.ActiveWorkerGroup, 0, len(values))
	for _, value := range values {
		result = append(result, &analyticsv1.ActiveWorkerGroup{
			Dimension: value.Dimension, Key: value.Key,
			ActiveMembers: value.ActiveMembers, Available: value.Available, OnShift: value.OnShift,
		})
	}
	return result
}

// dispatchFailureBreakdowns преобразует группы отказов с числом и долей в protobuf,
// сохраняя порядок и значения, рассчитанные сервисом.
func dispatchFailureBreakdowns(values []models.DispatchFailureBreakdown) []*analyticsv1.DispatchFailureBreakdown {
	result := make([]*analyticsv1.DispatchFailureBreakdown, 0, len(values))
	for _, value := range values {
		result = append(result, &analyticsv1.DispatchFailureBreakdown{Key: value.Key, Count: value.Count, Percent: value.Percent})
	}
	return result
}

// dispatchFailureReasons преобразует причины отказа с числом и долей запросов
// в protobuf, сохраняя порядок.
func dispatchFailureReasons(values []models.DispatchFailureReasonSummary) []*analyticsv1.DispatchFailureReasonSummary {
	result := make([]*analyticsv1.DispatchFailureReasonSummary, 0, len(values))
	for _, value := range values {
		result = append(result, &analyticsv1.DispatchFailureReasonSummary{
			Reason: value.Reason, Count: value.Count, RequestRate: value.RequestRate,
		})
	}
	return result
}

// dispatchFailureReasonDimensions преобразует причины отказа по измерениям
// с числом и долей причины в protobuf, сохраняя порядок.
func dispatchFailureReasonDimensions(values []models.DispatchFailureReasonDimension) []*analyticsv1.DispatchFailureReasonDimension {
	result := make([]*analyticsv1.DispatchFailureReasonDimension, 0, len(values))
	for _, value := range values {
		result = append(result, &analyticsv1.DispatchFailureReasonDimension{
			Reason: value.Reason, Key: value.Key, Count: value.Count, ReasonPercent: value.ReasonPercent,
		})
	}
	return result
}

// latencyDistribution переносит размер выборки, среднее, медиану и перцентили
// длительности в секундах в protobuf без пересчёта.
func latencyDistribution(value models.LatencyDistribution) *analyticsv1.LatencyDistribution {
	return &analyticsv1.LatencyDistribution{
		SampleCount:    value.SampleCount,
		AverageSeconds: value.AverageSeconds,
		MedianSeconds:  value.MedianSeconds,
		P90Seconds:     value.P90Seconds,
		P95Seconds:     value.P95Seconds,
		P99Seconds:     value.P99Seconds,
	}
}

// dispatchModeEffectiveness преобразует показатели режима назначения и распределение
// его длительности в protobuf.
func dispatchModeEffectiveness(value models.DispatchModeEffectiveness) *analyticsv1.DispatchModeEffectiveness {
	return &analyticsv1.DispatchModeEffectiveness{
		Mode: value.Mode, Requested: value.Requested, Assigned: value.Assigned,
		SuccessRate: value.SuccessRate, AssignmentTime: latencyDistribution(value.AssignmentTime),
	}
}

// assetBreakdown преобразует группу событий объектов со счётчиками инцидентов,
// повторов, ремонтов и обновлений критического риска в protobuf.
func assetBreakdown(value models.AssetBreakdown) *analyticsv1.AssetBreakdown {
	return &analyticsv1.AssetBreakdown{
		Key:                 value.Key,
		Incidents:           value.Incidents,
		RepeatedIncidents:   value.Repeated,
		Repairs:             value.Repairs,
		CriticalRiskUpdates: value.Critical,
	}
}
