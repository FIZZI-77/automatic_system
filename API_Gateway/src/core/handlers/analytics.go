package handlers

import (
	"context"
	"net/http"
	"strings"

	"gateway/models"

	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AnalyticsHandler struct {
	client analyticsv1.AnalyticsServiceClient
}

// NewAnalyticsHandler создаёт HTTP-обработчик аналитики с переданным gRPC-клиентом.
func NewAnalyticsHandler(c analyticsv1.AnalyticsServiceClient) *AnalyticsHandler {
	return &AnalyticsHandler{client: c}
}

// Overview разбирает JSON фильтра и запрашивает сводку заявок с метаданными
// пользователя; успешный ответ возвращает с HTTP 200 через dispatchResponse.
func (h *AnalyticsHandler) Overview(c *gin.Context) {
	var v models.AnalyticsRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.GetTicketOverview(analyticsContext(c), &analyticsv1.GetTicketOverviewRequest{
		Filter: analyticsFilter(v.Filter),
	})
	dispatchResponse(c, http.StatusOK, e, x)
}

// SLA преобразует JSON фильтра и запрашивает сводку SLA у Analytics Service;
// проверку ролей выполняет сервис, успех даёт HTTP 200.
func (h *AnalyticsHandler) SLA(c *gin.Context) {
	var v models.AnalyticsRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.GetSLASummary(analyticsContext(c), &analyticsv1.GetSLASummaryRequest{
		Filter: analyticsFilter(v.Filter),
	})
	dispatchResponse(c, http.StatusOK, e, x)
}

// Breakdown преобразует JSON фильтра, измерение и лимит и запрашивает группировку
// заявок; неизвестное измерение даёт нулевой enum для проверки сервисом.
func (h *AnalyticsHandler) Breakdown(c *gin.Context) {
	var v models.AnalyticsBreakdownRequest

	if !bindJSON(c, &v) {
		return
	}

	d := analyticsv1.BreakdownDimension(analyticsv1.BreakdownDimension_value["BREAKDOWN_DIMENSION_"+strings.ToUpper(v.Dimension)])
	x, e := h.client.ListTicketBreakdown(analyticsContext(c), &analyticsv1.ListTicketBreakdownRequest{
		Filter:    analyticsFilter(v.Filter),
		Dimension: d,
		Limit:     v.Limit,
	})
	dispatchResponse(c, http.StatusOK, e, x)
}

// Daily разбирает JSON фильтра и возвращает дневные метрики Analytics Service
// с HTTP 200 при успехе, преобразуя gRPC-ошибки через dispatchResponse.
func (h *AnalyticsHandler) Daily(c *gin.Context) {
	var v models.AnalyticsRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.ListDailyTicketMetrics(analyticsContext(c), &analyticsv1.ListDailyTicketMetricsRequest{
		Filter: analyticsFilter(v.Filter),
	})
	dispatchResponse(c, http.StatusOK, e, x)
}

// Assets передаёт JSON фильтра, типа объекта и района в Analytics Service
// и возвращает сводку объектов с HTTP 200 при успехе.
func (h *AnalyticsHandler) Assets(c *gin.Context) {
	var v models.AssetAnalyticsRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.GetAssetSummary(analyticsContext(c), &analyticsv1.GetAssetSummaryRequest{
		Filter:    analyticsFilter(v.Filter),
		AssetType: v.AssetType,
		District:  v.District,
	})
	dispatchResponse(c, http.StatusOK, e, x)
}

// OperationalLatency преобразует JSON фильтра и измерение группировки и запрашивает
// распределения задержек; ответ и ошибки отдаёт через dispatchResponse.
func (h *AnalyticsHandler) OperationalLatency(c *gin.Context) {
	var request models.OperationalLatencyRequest

	if !bindJSON(c, &request) {
		return
	}

	response, err := h.client.GetOperationalLatency(
		analyticsContext(c),
		&analyticsv1.GetOperationalLatencyRequest{
			Filter:  analyticsFilter(request.Filter),
			GroupBy: operationalLatencyDimension(request.GroupBy),
		},
	)
	dispatchResponse(c, http.StatusOK, err, response)
}

// DispatchFailures запрашивает сводку отказов назначения по JSON-фильтру
// с метаданными пользователя; успех даёт HTTP 200.
func (h *AnalyticsHandler) DispatchFailures(c *gin.Context) {
	var request models.AnalyticsRequest

	if !bindJSON(c, &request) {
		return
	}

	response, err := h.client.GetDispatchFailureSummary(analyticsContext(c), &analyticsv1.GetDispatchFailureSummaryRequest{
		Filter: analyticsFilter(request.Filter),
	})
	dispatchResponse(c, http.StatusOK, err, response)
}

// BrigadeWorkload запрашивает нагрузку бригад по JSON-фильтру
// и возвращает ответ сервиса с HTTP 200 при успехе.
func (h *AnalyticsHandler) BrigadeWorkload(c *gin.Context) {
	var request models.AnalyticsRequest

	if !bindJSON(c, &request) {
		return
	}

	response, err := h.client.GetBrigadeWorkload(analyticsContext(c), &analyticsv1.GetBrigadeWorkloadRequest{
		Filter: analyticsFilter(request.Filter),
	})
	dispatchResponse(c, http.StatusOK, err, response)
}

// ActiveWorkers запрашивает численность активных участников по JSON-фильтру
// и возвращает ответ сервиса с HTTP 200 при успехе.
func (h *AnalyticsHandler) ActiveWorkers(c *gin.Context) {
	var request models.AnalyticsRequest

	if !bindJSON(c, &request) {
		return
	}

	response, err := h.client.GetActiveWorkers(analyticsContext(c), &analyticsv1.GetActiveWorkersRequest{
		Filter: analyticsFilter(request.Filter),
	})
	dispatchResponse(c, http.StatusOK, err, response)
}

// AssignmentFunnel запрашивает воронку назначения по JSON-фильтру;
// ответ и gRPC-ошибки отдаёт через dispatchResponse.
func (h *AnalyticsHandler) AssignmentFunnel(c *gin.Context) {
	var request models.AnalyticsRequest

	if !bindJSON(c, &request) {
		return
	}

	response, err := h.client.GetAssignmentFunnel(analyticsContext(c), &analyticsv1.GetAssignmentFunnelRequest{
		Filter: analyticsFilter(request.Filter),
	})
	dispatchResponse(c, http.StatusOK, err, response)
}

// DispatchEffectiveness передаёт JSON-фильтр сервису сравнения режимов назначения
// и возвращает его ответ с HTTP 200 при успехе.
func (h *AnalyticsHandler) DispatchEffectiveness(c *gin.Context) {
	var request models.AnalyticsRequest

	if !bindJSON(c, &request) {
		return
	}

	response, err := h.client.GetDispatchEffectiveness(
		analyticsContext(c),
		&analyticsv1.GetDispatchEffectivenessRequest{
			Filter: analyticsFilter(request.Filter),
		},
	)
	dispatchResponse(c, http.StatusOK, err, response)
}

// OperationalInsights запрашивает операционные показатели и прогноз по JSON-фильтру;
// вычисления выполняет Analytics Service, успешный ответ получает HTTP 200.
func (h *AnalyticsHandler) OperationalInsights(c *gin.Context) {
	var request models.AnalyticsRequest

	if !bindJSON(c, &request) {
		return
	}

	response, err := h.client.GetOperationalInsights(
		analyticsContext(c),
		&analyticsv1.GetOperationalInsightsRequest{
			Filter: analyticsFilter(request.Filter),
		},
	)
	dispatchResponse(c, http.StatusOK, err, response)
}

// ProjectionHealth без разбора тела запрашивает состояние проекций событий
// с метаданными пользователя; успешный ответ получает HTTP 200.
func (h *AnalyticsHandler) ProjectionHealth(c *gin.Context) {
	response, err := h.client.GetProjectionHealth(analyticsContext(c), &analyticsv1.GetProjectionHealthRequest{})
	dispatchResponse(c, http.StatusOK, err, response)
}

// DispatchOperations запрашивает операции назначения по JSON-фильтру
// с фиксированным лимитом 25; успешный ответ получает HTTP 200.
func (h *AnalyticsHandler) DispatchOperations(c *gin.Context) {
	var request models.AnalyticsRequest

	if !bindJSON(c, &request) {
		return
	}

	response, err := h.client.ListDispatchOperations(
		analyticsContext(c),
		&analyticsv1.ListDispatchOperationsRequest{
			Filter: analyticsFilter(request.Filter),
			Limit:  25,
		},
	)
	dispatchResponse(c, http.StatusOK, err, response)
}

// BrigadePerformance запрашивает результативность бригад по JSON-фильтру
// и возвращает ответ сервиса с HTTP 200 при успехе.
func (h *AnalyticsHandler) BrigadePerformance(c *gin.Context) {
	var request models.AnalyticsRequest

	if !bindJSON(c, &request) {
		return
	}

	response, err := h.client.GetBrigadePerformance(
		analyticsContext(c),
		&analyticsv1.GetBrigadePerformanceRequest{
			Filter: analyticsFilter(request.Filter),
		},
	)
	dispatchResponse(c, http.StatusOK, err, response)
}

// DepartmentPerformance запрашивает результативность ведомств по JSON-фильтру;
// проверку административной роли выполняет Analytics Service по метаданным пользователя.
func (h *AnalyticsHandler) DepartmentPerformance(c *gin.Context) {
	var request models.AnalyticsRequest

	if !bindJSON(c, &request) {
		return
	}

	response, err := h.client.GetDepartmentPerformance(
		analyticsContext(c),
		&analyticsv1.GetDepartmentPerformanceRequest{Filter: analyticsFilter(request.Filter)},
	)

	dispatchResponse(c, http.StatusOK, err, response)
}

// analyticsContext создаёт через dispatchContext RPC-контекст с таймаутом 20 секунд
// и метаданными пользователя; cancel затем вызывает dispatchResponse.
func analyticsContext(c *gin.Context) context.Context {
	return dispatchContext(c)
}

// operationalLatencyDimension нормализует регистр и пробелы измерения задержек;
// неизвестное значение даёт нулевой enum.
func operationalLatencyDimension(value string) analyticsv1.OperationalLatencyDimension {
	key := "OPERATIONAL_LATENCY_DIMENSION_" + strings.ToUpper(strings.TrimSpace(value))
	return analyticsv1.OperationalLatencyDimension(analyticsv1.OperationalLatencyDimension_value[key])
}

// analyticsFilter преобразует временные границы в protobuf и сохраняет
// необязательные условия без проверки форматов; nil сохраняет как nil.
func analyticsFilter(v *models.AnalyticsFilter) *analyticsv1.AnalyticsFilter {

	if v == nil {
		return nil
	}

	x := &analyticsv1.AnalyticsFilter{
		DepartmentId:   v.DepartmentID,
		CategoryId:     v.CategoryID,
		Priority:       v.Priority,
		BrigadeId:      v.BrigadeID,
		AssignmentMode: v.AssignmentMode,
		FailureCode:    v.FailureCode,
		Success:        v.Success,
	}

	if v.From != nil {
		x.From = timestamppb.New(*v.From)
	}

	if v.To != nil {
		x.To = timestamppb.New(*v.To)
	}

	return x
}
