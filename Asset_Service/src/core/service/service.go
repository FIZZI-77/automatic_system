package service

import (
	"asset/models"
	"asset/src/core/repository"
	"context"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"time"
)

type AssetService interface {
	// Create проверяет параметры и создаёт объект при переданном разрешении; иначе возвращает ErrForbidden.
	Create(context.Context, models.CreateInput, bool) (*models.Asset, error)
	// Update изменяет заданные поля объекта при переданном разрешении с проверкой критичности.
	Update(context.Context, models.UpdateInput, bool) (*models.Asset, error)
	// Get возвращает объект по ID либо ошибку хранилища.
	Get(context.Context, uuid.UUID) (*models.Asset, error)
	// List возвращает страницу объектов по фильтрам и общее количество совпадений.
	List(context.Context, models.Filter) ([]*models.Asset, int64, error)
	// ChangeStatus меняет статус с автором и причиной при переданном разрешении.
	ChangeStatus(context.Context, uuid.UUID, models.Status, uuid.UUID, string, bool) (*models.Asset, error)
	// Nearby ищет объекты в радиусе в метрах от широты и долготы, по возрастанию расстояния.
	Nearby(context.Context, float64, float64, float64, *string, int32) ([]*models.Asset, error)
	// Incident при переданном разрешении сохраняет инцидент и затем пересчитывает риск объекта.
	Incident(context.Context, models.Incident, bool) (*models.Incident, *models.Prediction, error)
	// Repair при переданном разрешении сохраняет завершённый ремонт и затем пересчитывает риск.
	Repair(context.Context, models.Repair, bool) (*models.Repair, *models.Prediction, error)
	// Inspection при переданном разрешении сохраняет осмотр с оценкой 0–1 и затем пересчитывает риск.
	Inspection(context.Context, models.Inspection, bool) (*models.Inspection, *models.Prediction, error)
	// CreatePlan создаёт или обновляет план с положительным интервалом при переданном разрешении.
	CreatePlan(context.Context, models.Plan, bool) (*models.Plan, error)
	// Due возвращает страницу активных планов со сроком до указанного момента и общий счётчик.
	Due(context.Context, *uuid.UUID, time.Time, int32, int32) ([]*models.Plan, int64, error)
	// Prediction возвращает последний риск объекта либо рассчитывает и сохраняет его при отсутствии.
	Prediction(context.Context, uuid.UUID) (*models.Prediction, error)
	// Recalculate при переданном разрешении пересчитывает риски ведомства или всех объектов при nil ведомстве.
	// Возвращает число успешных расчётов до первой ошибки.
	Recalculate(context.Context, *uuid.UUID, bool) (int64, error)
}
type Service struct{ AssetService }

// NewService объединяет операции объектов и расчёта риска с хранилищем r.
// nil l допускается и отключает вывод журнала.
func NewService(r repository.AssetRepository, l *zap.Logger) *Service {
	return &Service{
		AssetService: &AssetServiceStruct{
			repo: r,
			log:  l,
		},
	}
}
