package handlers

import (
	"context"
	"gateway/models"
	"net/http"
	"time"

	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"github.com/gin-gonic/gin"
)

type DepartmentHandler struct {
	departmentClient departmentv1.DepartmentServiceClient
}

// NewDepartmentHandler создаёт HTTP-обработчик ведомств с переданным gRPC-клиентом.
func NewDepartmentHandler(departmentClient departmentv1.DepartmentServiceClient) *DepartmentHandler {
	return &DepartmentHandler{departmentClient: departmentClient}
}

// CreateDepartment разбирает JSON имени и описания и вызывает Department Service
// с метаданными пользователя и таймаутом 5 секунд; успех даёт HTTP 201 с ведомством.
func (dh *DepartmentHandler) CreateDepartment(c *gin.Context) {
	var req models.CreateDepartmentRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

	res, err := dh.departmentClient.CreateDepartment(ctx, &departmentv1.CreateDepartmentRequest{
		Name:        req.Name,
		Description: req.Description,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusCreated, &models.CreateDepartmentResponse{
		Department: FromProtoDepartment(res.GetDepartment()),
	})
}

// GetDepartmentByID разбирает ID из JSON и запрашивает ведомство с метаданными
// пользователя и таймаутом 5 секунд; при успехе возвращает HTTP 200 с HTTP-моделью.
func (dh *DepartmentHandler) GetDepartmentByID(c *gin.Context) {
	var req models.GetDepartmentByIDRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

	res, err := dh.departmentClient.GetDepartmentByID(ctx, &departmentv1.GetDepartmentByIDRequest{
		Id: req.ID,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.GetDepartmentByIDResponse{
		Department: FromProtoDepartment(res.GetDepartment()),
	})
}

// ListDepartments проверяет JSON и даты фильтра, вызывает список ведомств
// с метаданными пользователя и таймаутом 5 секунд и возвращает HTTP 200
// со страницей HTTP-моделей и общим счётчиком.
func (dh *DepartmentHandler) ListDepartments(c *gin.Context) {
	var req models.ListDepartmentsRequest

	if !bindJSON(c, &req) {
		return
	}

	protoReq, ok := buildListDepartmentsRequest(c, &req)

	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

	res, err := dh.departmentClient.ListDepartments(ctx, protoReq)

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	departments := make([]*models.Department, 0, len(res.GetDepartments()))
	for _, department := range res.GetDepartments() {
		departments = append(departments, FromProtoDepartment(department))
	}

	c.JSON(http.StatusOK, &models.ListDepartmentsResponse{
		Departments: departments,
		Total:       res.GetTotal(),
	})
}

// UpdateDepartment преобразует заданные поля JSON в запрос обновления ведомства
// с метаданными пользователя и таймаутом 5 секунд; успешный ответ даёт HTTP 200.
func (dh *DepartmentHandler) UpdateDepartment(c *gin.Context) {
	var req models.UpdateDepartmentRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

	res, err := dh.departmentClient.UpdateDepartment(ctx, buildUpdateDepartmentRequest(&req))

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.UpdateDepartmentResponse{
		Department: FromProtoDepartment(res.GetDepartment()),
	})
}

// DeleteDepartment разбирает ID из JSON и передаёт удаление сервису с метаданными
// пользователя и таймаутом 5 секунд; возвращает ведомство из результата с HTTP 200.
func (dh *DepartmentHandler) DeleteDepartment(c *gin.Context) {
	var req models.DeleteDepartmentRequest

	if !bindJSON(c, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ctx = ticketActorContext(ctx, c)

	res, err := dh.departmentClient.DeleteDepartment(ctx, &departmentv1.DeleteDepartmentRequest{
		Id: req.ID,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, &models.DeleteDepartmentResponse{
		Department: FromProtoDepartment(res.GetDepartment()),
	})
}

// buildListDepartmentsRequest преобразует фильтры, сортировку и пагинацию,
// разбирая даты RFC3339. Неверная дата записывает HTTP 400 и даёт nil, false;
// вызывающий код при false прекращает обработку.
func buildListDepartmentsRequest(c *gin.Context, req *models.ListDepartmentsRequest) (*departmentv1.ListDepartmentsRequest, bool) {
	protoReq := &departmentv1.ListDepartmentsRequest{
		Limit:  int32OrZero(req.Limit),
		Offset: int32OrZero(req.Offset),
	}

	if req.Status != nil {
		status := ToProtoDepartmentStatus(*req.Status)
		protoReq.Status = &status
	}

	if req.SortBy != nil {
		sortBy := ToProtoDepartmentSortBy(*req.SortBy)
		protoReq.SortBy = &sortBy
	}

	if req.SortOrder != nil {
		sortOrder := ToProtoDepartmentSortOrder(*req.SortOrder)
		protoReq.SortOrder = &sortOrder
	}

	if req.CreatedFrom != nil {
		createdFrom, err := ToProtoTimestamp(*req.CreatedFrom)

		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid created_from"})
			return nil, false
		}

		protoReq.CreatedFrom = createdFrom
	}

	if req.CreatedTo != nil {
		createdTo, err := ToProtoTimestamp(*req.CreatedTo)

		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid created_to"})
			return nil, false
		}

		protoReq.CreatedTo = createdTo
	}

	return protoReq, true
}

// buildUpdateDepartmentRequest сохраняет необязательность имени, описания
// и статуса при преобразовании HTTP-запроса в protobuf.
func buildUpdateDepartmentRequest(req *models.UpdateDepartmentRequest) *departmentv1.UpdateDepartmentRequest {
	protoReq := &departmentv1.UpdateDepartmentRequest{
		Id:          req.ID,
		Name:        req.Name,
		Description: req.Description,
	}

	if req.Status != nil {
		status := ToProtoDepartmentStatus(*req.Status)
		protoReq.Status = &status
	}

	return protoReq
}
