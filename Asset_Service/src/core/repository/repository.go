package repository

import (
	"asset/models"
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RiskFacts struct {
	InstallationYear      *int32
	ServiceLifeYears      *int32
	Criticality           float64
	Incidents90           int
	Incidents365          int
	Repeat90              int
	SLAIncidents90        int
	DaysSinceRepair       int
	DaysInspectionOverdue int
	LastCondition         *float64
}
type AssetRepository interface {
	// Create сохраняет объект с геометрией и событием создания в одной транзакции.
	Create(context.Context, models.CreateInput) (*models.Asset, error)
	// Update заменяет заданные поля объекта и сохраняет событие outbox.
	Update(context.Context, models.UpdateInput) (*models.Asset, error)
	// Get возвращает объект по ID либо pgx.ErrNoRows.
	Get(context.Context, uuid.UUID) (*models.Asset, error)
	// List возвращает страницу объектов по фильтрам от новых к старым и общий счётчик.
	List(context.Context, models.Filter) ([]*models.Asset, int64, error)
	// ChangeStatus сохраняет статус объекта, историю с автором и причиной и событие outbox.
	ChangeStatus(context.Context, uuid.UUID, models.Status, uuid.UUID, string) (*models.Asset, error)
	// Nearby возвращает объекты в радиусе в метрах по возрастанию расстояния от широты и долготы.
	Nearby(context.Context, float64, float64, float64, *string, int32) ([]*models.Asset, error)
	// RecordIncident сохраняет инцидент с признаком повтора, переводит объект в DAMAGED и записывает outbox.
	RecordIncident(context.Context, models.Incident) (*models.Incident, error)
	// CompleteRepair сохраняет ремонт, переводит объект в ACTIVE и записывает событие outbox.
	CompleteRepair(context.Context, models.Repair) (*models.Repair, error)
	// RecordInspection сохраняет осмотр, обновляет срок следующего и записывает событие outbox.
	RecordInspection(context.Context, models.Inspection) (*models.Inspection, error)
	// CreatePlan создаёт или обновляет активный план для пары объект–вид обслуживания.
	CreatePlan(context.Context, models.Plan) (*models.Plan, error)
	// DuePlans возвращает страницу активных планов со сроком не позднее указанного момента и общий счётчик.
	DuePlans(context.Context, *uuid.UUID, time.Time, int32, int32) ([]*models.Plan, int64, error)
	// RiskFacts собирает характеристики, отказы, сроки и оценку состояния объекта для расчёта риска.
	RiskFacts(context.Context, uuid.UUID, time.Time) (RiskFacts, error)
	// SavePrediction сохраняет расчёт и текущий риск объекта с outbox, отдельно отмечая вход в CRITICAL.
	SavePrediction(context.Context, models.Prediction) error
	// GetPrediction возвращает последний расчёт риска объекта либо pgx.ErrNoRows.
	GetPrediction(context.Context, uuid.UUID) (*models.Prediction, error)
	// ListIDs возвращает ID объектов ведомства либо всех объектов при nil ведомстве.
	ListIDs(context.Context, *uuid.UUID) ([]uuid.UUID, error)
}
type Repository struct{ AssetRepository }

// NewRepository объединяет операции хранилища объектов, обслуживания и риска с пулом db.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{AssetRepository: NewAssetRepoStruct(db)}
}

// IsNotFound проверяет наличие pgx.ErrNoRows в цепочке e.
func IsNotFound(e error) bool {
	return errors.Is(e, pgx.ErrNoRows)
}
