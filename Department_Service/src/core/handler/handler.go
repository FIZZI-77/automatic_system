package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"department/models"
	"department/pkg"
	"department/src/core/service"

	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type DepartmentHandler struct {
	departmentv1.UnimplementedDepartmentServiceServer
	service *service.Service
	logger  *zap.Logger
}

type actorContext struct {
	Roles []string
}

// NewDepartmentHandler создаёт gRPC-обработчик ведомств с сервисом и журналом запросов.
func NewDepartmentHandler(service *service.Service, logger *zap.Logger) *DepartmentHandler {
	return &DepartmentHandler{service: service, logger: logger}
}

// CreateDepartment передаёт имя, описание и роли из входящих метаданных сервису
// создания ведомства; проверку прав выполняет сервис, ответ преобразуется в protobuf.
func (h *DepartmentHandler) CreateDepartment(ctx context.Context, req *departmentv1.CreateDepartmentRequest) (*departmentv1.CreateDepartmentResponse, error) {
	start := time.Now()
	logger := h.logger.With(pkg.RequestIDField(ctx))

	logger.Info("gRPC request received",
		zap.String("method", "CreateDepartment"),
		zap.String("name", req.GetName()),
	)

	in := &models.CreateDepartmentInput{
		Name:        req.GetName(),
		Description: req.GetDescription(),
		ActorRoles:  actorFromContext(ctx).Roles,
	}

	res, err := h.service.CreateDepartment(ctx, in)

	if err != nil {
		logger.Warn("gRPC request failed",
			zap.String("method", "CreateDepartment"),
			zap.String("name", req.GetName()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, departmentStatusError("CreateDepartment", err)
	}

	logger.Info("gRPC request succeeded",
		zap.String("method", "CreateDepartment"),
		zap.String("department_id", res.Department.ID.String()),
		zap.String("name", res.Department.Name),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return &departmentv1.CreateDepartmentResponse{Department: ToProtoDepartment(res.Department)}, nil
}

// GetDepartmentByID разбирает UUID ведомства и возвращает результат сервиса
// в protobuf; неверный UUID даёт InvalidArgument, отсутствие ведомства — NotFound.
func (h *DepartmentHandler) GetDepartmentByID(ctx context.Context, req *departmentv1.GetDepartmentByIDRequest) (*departmentv1.GetDepartmentByIDResponse, error) {
	start := time.Now()
	logger := h.logger.With(pkg.RequestIDField(ctx))

	logger.Info("gRPC request received",
		zap.String("method", "GetDepartmentByID"),
		zap.String("department_id", req.GetId()),
	)

	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		logger.Warn("gRPC request failed",
			zap.String("method", "GetDepartmentByID"),
			zap.String("department_id", req.GetId()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, departmentStatusError("GetDepartmentByID", fmt.Errorf("%w: %v", models.ErrValidation, err))
	}

	res, err := h.service.GetDepartmentByID(ctx, &models.GetDepartmentByIDInput{ID: id})

	if err != nil {
		logger.Warn("gRPC request failed",
			zap.String("method", "GetDepartmentByID"),
			zap.String("department_id", req.GetId()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, departmentStatusError("GetDepartmentByID", err)
	}

	logger.Info("gRPC request succeeded",
		zap.String("method", "GetDepartmentByID"),
		zap.String("department_id", res.Department.ID.String()),
		zap.String("name", res.Department.Name),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return &departmentv1.GetDepartmentByIDResponse{Department: ToProtoDepartment(res.Department)}, nil
}

// ListDepartments преобразует фильтры дат, сортировку и пагинацию и возвращает
// страницу ведомств с общим счётчиком. Отсутствующий статус и UNSPECIFIED не фильтруют список.
func (h *DepartmentHandler) ListDepartments(ctx context.Context, req *departmentv1.ListDepartmentsRequest) (*departmentv1.ListDepartmentsResponse, error) {
	start := time.Now()
	logger := h.logger.With(pkg.RequestIDField(ctx))

	logger.Info("gRPC request received",
		zap.String("method", "ListDepartments"),
		zap.Int32("limit", req.GetLimit()),
		zap.Int32("offset", req.GetOffset()),
	)

	var statusValue *models.DepartmentStatus

	if req.Status != nil && req.GetStatus() != departmentv1.DepartmentStatus_DEPARTMENT_STATUS_UNSPECIFIED {
		departmentStatus := FromProtoStatus(req.GetStatus())
		statusValue = &departmentStatus
	}

	in := &models.ListDepartmentsInput{
		Status:      statusValue,
		CreatedFrom: FromProtoTimestamp(req.GetCreatedFrom()),
		CreatedTo:   FromProtoTimestamp(req.GetCreatedTo()),
		Limit:       req.GetLimit(),
		Offset:      req.GetOffset(),
	}

	if req.SortBy != nil {
		in.SortBy = FromProtoSortBy(req.GetSortBy())
	}

	if req.SortOrder != nil {
		in.SortOrder = FromProtoSortOrder(req.GetSortOrder())
	}

	res, err := h.service.ListDepartments(ctx, in)

	if err != nil {
		logger.Warn("gRPC request failed",
			zap.String("method", "ListDepartments"),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, departmentStatusError("ListDepartments", err)
	}

	departments := make([]*departmentv1.Department, 0, len(res.Departments))
	for _, item := range res.Departments {
		departments = append(departments, ToProtoDepartment(item))
	}

	logger.Info("gRPC request succeeded",
		zap.String("method", "ListDepartments"),
		zap.Int("count", len(departments)),
		zap.Int64("total", res.Total),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return &departmentv1.ListDepartmentsResponse{Departments: departments, Total: res.Total}, nil
}

// UpdateDepartment разбирает UUID, сохраняет необязательность имени и описания
// и передаёт изменение с ролями из метаданных сервису; UNSPECIFIED-статус пропускает.
func (h *DepartmentHandler) UpdateDepartment(ctx context.Context, req *departmentv1.UpdateDepartmentRequest) (*departmentv1.UpdateDepartmentResponse, error) {
	start := time.Now()
	logger := h.logger.With(pkg.RequestIDField(ctx))

	logger.Info("gRPC request received",
		zap.String("method", "UpdateDepartment"),
		zap.String("department_id", req.GetId()),
	)

	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		logger.Warn("gRPC request failed",
			zap.String("method", "UpdateDepartment"),
			zap.String("department_id", req.GetId()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, departmentStatusError("UpdateDepartment", fmt.Errorf("%w: %v", models.ErrValidation, err))
	}

	var statusValue *models.DepartmentStatus

	if req.Status != nil && req.GetStatus() != departmentv1.DepartmentStatus_DEPARTMENT_STATUS_UNSPECIFIED {
		departmentStatus := FromProtoStatus(req.GetStatus())
		statusValue = &departmentStatus
	}

	res, err := h.service.UpdateDepartment(ctx, &models.UpdateDepartmentInput{
		ID:          id,
		Name:        req.Name,
		Description: req.Description,
		Status:      statusValue,
		ActorRoles:  actorFromContext(ctx).Roles,
	})

	if err != nil {
		logger.Warn("gRPC request failed",
			zap.String("method", "UpdateDepartment"),
			zap.String("department_id", req.GetId()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, departmentStatusError("UpdateDepartment", err)
	}

	logger.Info("gRPC request succeeded",
		zap.String("method", "UpdateDepartment"),
		zap.String("department_id", res.Department.ID.String()),
		zap.String("status", string(res.Department.Status)),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return &departmentv1.UpdateDepartmentResponse{Department: ToProtoDepartment(res.Department)}, nil
}

// DeleteDepartment разбирает UUID и передаёт запрос удаления с ролями из метаданных
// сервису; возвращает ведомство из результата, ошибки преобразует в коды gRPC.
func (h *DepartmentHandler) DeleteDepartment(ctx context.Context, req *departmentv1.DeleteDepartmentRequest) (*departmentv1.DeleteDepartmentResponse, error) {
	start := time.Now()
	logger := h.logger.With(pkg.RequestIDField(ctx))

	logger.Info("gRPC request received",
		zap.String("method", "DeleteDepartment"),
		zap.String("department_id", req.GetId()),
	)

	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		logger.Warn("gRPC request failed",
			zap.String("method", "DeleteDepartment"),
			zap.String("department_id", req.GetId()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, departmentStatusError("DeleteDepartment", fmt.Errorf("%w: %v", models.ErrValidation, err))
	}

	res, err := h.service.DeleteDepartment(ctx, &models.DeleteDepartmentInput{
		ID:         id,
		ActorRoles: actorFromContext(ctx).Roles,
	})

	if err != nil {
		logger.Warn("gRPC request failed",
			zap.String("method", "DeleteDepartment"),
			zap.String("department_id", req.GetId()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, departmentStatusError("DeleteDepartment", err)
	}

	logger.Info("gRPC request succeeded",
		zap.String("method", "DeleteDepartment"),
		zap.String("department_id", res.Department.ID.String()),
		zap.String("status", string(res.Department.Status)),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return &departmentv1.DeleteDepartmentResponse{Department: ToProtoDepartment(res.Department)}, nil
}

// parseUUID разбирает UUID либо возвращает uuid.Nil и ошибку с именем поля.
func parseUUID(value string, field string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)

	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid %s: %w", field, err)
	}

	return parsed, nil
}

// actorFromContext читает все x-actor-roles из входящих метаданных, разделяет
// запятыми, обрезает крайние пробелы и исключает пустые роли, сохраняя регистр.
func actorFromContext(ctx context.Context) actorContext {
	md, ok := metadata.FromIncomingContext(ctx)

	if !ok {
		return actorContext{}
	}

	var actor actorContext

	if values := md.Get("x-actor-roles"); len(values) > 0 {
		for _, value := range values {
			for _, role := range strings.Split(value, ",") {
				role = strings.TrimSpace(role)

				if role != "" {
					actor.Roles = append(actor.Roles, role)
				}

			}
		}
	}

	return actor
}

// departmentStatusError формирует gRPC-ошибку с доменным кодом, именем метода
// и исходным текстом; предназначена для ненулевой ошибки.
func departmentStatusError(method string, err error) error {
	return status.Errorf(departmentErrorCode(err), "failed %s: %v", method, err)
}

// departmentErrorCode сопоставляет валидацию, отсутствие, дубликат и запрет доступа
// кодам gRPC; незавершённая идемпотентная операция даёт Aborted, неудачная —
// FailedPrecondition. nil даёт OK, неизвестная ошибка — Internal.
func departmentErrorCode(err error) codes.Code {

	if err == nil {
		return codes.OK
	}

	switch {
	case errors.Is(err, models.ErrValidation):
		return codes.InvalidArgument
	case errors.Is(err, models.ErrNotFound):
		return codes.NotFound
	case errors.Is(err, models.ErrAlreadyExists):
		return codes.AlreadyExists
	case errors.Is(err, models.ErrIdempotencyConflict):
		return codes.AlreadyExists
	case errors.Is(err, models.ErrIdempotencyInProgress):
		return codes.Aborted
	case errors.Is(err, models.ErrIdempotencyFailed):
		return codes.FailedPrecondition
	case errors.Is(err, models.ErrPermissionDenied):
		return codes.PermissionDenied
	default:
		return codes.Internal
	}
}
