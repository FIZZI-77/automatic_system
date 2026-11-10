package handlers

import (
	"net/http"
	"strings"

	"gateway/models"

	slav1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/sla/v1"
	"github.com/gin-gonic/gin"
)

type SLAHandler struct {
	client slav1.SLAServiceClient
}

// NewSLAHandler создаёт HTTP-обработчик SLA с переданным gRPC-клиентом.
func NewSLAHandler(c slav1.SLAServiceClient) *SLAHandler {
	return &SLAHandler{client: c}
}

// CreateRule преобразует JSON правила с длительностями в секундах и необязательными
// ограничениями и вызывает SLA Service с метаданными пользователя; успех даёт HTTP 201.
func (h *SLAHandler) CreateRule(c *gin.Context) {
	var v models.CreateSLARuleRequest

	if !bindJSON(c, &v) {
		return
	}

	q := &slav1.CreateRuleRequest{
		Name:                  v.Name,
		DepartmentId:          v.DepartmentID,
		CategoryId:            v.CategoryID,
		ResponseTimeSeconds:   v.ResponseTimeSeconds,
		ResolutionTimeSeconds: v.ResolutionTimeSeconds,
		WarningPercent:        v.WarningPercent,
	}

	if v.Priority != nil {
		p := slaPriority(*v.Priority)
		q.Priority = &p
	}

	x, e := h.client.CreateRule(dispatchContext(c), q)
	dispatchResponse(c, http.StatusCreated, e, x)
}

// UpdateRule передаёт заданные поля JSON и необязательный приоритет в SLA Service;
// проверку прав выполняет сервис, успешный ответ возвращается с HTTP 200.
func (h *SLAHandler) UpdateRule(c *gin.Context) {
	var v models.UpdateSLARuleRequest

	if !bindJSON(c, &v) {
		return
	}

	q := &slav1.UpdateRuleRequest{
		Id:                    v.ID,
		Name:                  v.Name,
		DepartmentId:          v.DepartmentID,
		CategoryId:            v.CategoryID,
		ResponseTimeSeconds:   v.ResponseTimeSeconds,
		ResolutionTimeSeconds: v.ResolutionTimeSeconds,
		WarningPercent:        v.WarningPercent,
		Active:                v.Active,
	}

	if v.Priority != nil {
		p := slaPriority(*v.Priority)
		q.Priority = &p
	}

	x, e := h.client.UpdateRule(dispatchContext(c), q)
	dispatchResponse(c, http.StatusOK, e, x)
}

// DeleteRule разбирает ID правила из JSON и вызывает удаление в SLA Service;
// ответ и ошибки переводит через dispatchResponse, успех даёт HTTP 200.
func (h *SLAHandler) DeleteRule(c *gin.Context) {
	var v models.SLAIDRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.DeleteRule(dispatchContext(c), &slav1.DeleteRuleRequest{
		Id: v.ID,
	})
	dispatchResponse(c, http.StatusOK, e, x)
}

// GetRule разбирает ID правила из JSON и возвращает ответ SLA Service с HTTP 200;
// ошибки gRPC преобразует через dispatchResponse.
func (h *SLAHandler) GetRule(c *gin.Context) {
	var v models.SLAIDRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.GetRule(dispatchContext(c), &slav1.GetRuleRequest{
		Id: v.ID,
	})
	dispatchResponse(c, http.StatusOK, e, x)
}

// ListRules сохраняет необязательные фильтры ведомства, категории, активности
// и приоритета, передаёт пагинацию SLA Service и возвращает его ответ с HTTP 200.
func (h *SLAHandler) ListRules(c *gin.Context) {
	var v models.ListSLARulesRequest

	if !bindJSON(c, &v) {
		return
	}

	q := &slav1.ListRulesRequest{
		DepartmentId: v.DepartmentID,
		CategoryId:   v.CategoryID,
		Active:       v.Active,
		Limit:        v.Limit,
		Offset:       v.Offset,
	}

	if v.Priority != nil {
		p := slaPriority(*v.Priority)
		q.Priority = &p
	}

	x, e := h.client.ListRules(dispatchContext(c), q)
	dispatchResponse(c, http.StatusOK, e, x)
}

// GetTicketSLA разбирает ID заявки из JSON и запрашивает её SLA с метаданными
// пользователя; успешный ответ возвращает с HTTP 200.
func (h *SLAHandler) GetTicketSLA(c *gin.Context) {
	var v models.TicketIDRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.GetTicketSLA(dispatchContext(c), &slav1.GetTicketSLARequest{
		TicketId: v.TicketID,
	})
	dispatchResponse(c, http.StatusOK, e, x)
}

// ListTicketSLAs преобразует необязательный статус, сохраняет фильтры ведомства
// и нарушения и передаёт пагинацию сервису; успех даёт HTTP 200.
func (h *SLAHandler) ListTicketSLAs(c *gin.Context) {
	var v models.ListTicketSLAsRequest

	if !bindJSON(c, &v) {
		return
	}

	q := &slav1.ListTicketSLAsRequest{
		DepartmentId: v.DepartmentID,
		Breached:     v.Breached,
		Limit:        v.Limit,
		Offset:       v.Offset,
	}

	if v.Status != nil {
		s := slaStatus(*v.Status)
		q.Status = &s
	}

	x, e := h.client.ListTicketSLAs(dispatchContext(c), q)
	dispatchResponse(c, http.StatusOK, e, x)
}

// ListHistory запрашивает историю SLA заявки из JSON с фиксированным лимитом 100
// и нулевым смещением; успешный ответ возвращает с HTTP 200.
func (h *SLAHandler) ListHistory(c *gin.Context) {
	var v models.TicketIDRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.ListHistory(dispatchContext(c), &slav1.ListHistoryRequest{
		TicketId: v.TicketID,
		Limit:    100,
	})
	dispatchResponse(c, http.StatusOK, e, x)
}

// slaPriority преобразует имя приоритета без учёта регистра;
// неизвестное имя даёт нулевой enum, пробелы не обрезаются.
func slaPriority(v string) slav1.TicketPriority {
	return slav1.TicketPriority(slav1.TicketPriority_value["TICKET_PRIORITY_"+strings.ToUpper(v)])
}

// slaStatus преобразует имя статуса SLA без учёта регистра;
// неизвестное имя даёт нулевой enum, пробелы не обрезаются.
func slaStatus(v string) slav1.SLAStatus {
	return slav1.SLAStatus(slav1.SLAStatus_value["SLA_STATUS_"+strings.ToUpper(v)])
}
