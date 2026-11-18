package repository

import (
	"context"
	"errors"
	"report/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ReportRepository interface {
	// Create сохраняет задание отчёта с событием создания в одной транзакции.
	Create(context.Context, models.CreateInput) (*models.Report, error)
	// Get возвращает задание по ID либо pgx.ErrNoRows.
	Get(context.Context, uuid.UUID) (*models.Report, error)
	// List возвращает страницу заданий по фильтрам от новых к старым и общий счётчик.
	List(context.Context, models.ListFilter) ([]*models.Report, int64, error)
	// Cancel отменяет PENDING или FAILED; недопустимое состояние даёт pgx.ErrNoRows.
	Cancel(context.Context, uuid.UUID) (*models.Report, error)
	// Retry возвращает FAILED в PENDING, сохраняя число попыток; иной статус даёт pgx.ErrNoRows.
	Retry(context.Context, uuid.UUID) (*models.Report, error)
	// Claim захватывает ожидающее или зависшее задание; отсутствие работы даёт pgx.ErrNoRows.
	Claim(context.Context) (*models.Report, error)
	// Complete сохраняет файл и COMPLETED для текущей попытки PROCESSING-задания вместе с outbox.
	Complete(context.Context, uuid.UUID, uuid.UUID, int32) error
	// Fail фиксирует FAILED и причину для текущей попытки PROCESSING-задания вместе с outbox.
	Fail(context.Context, uuid.UUID, int32, string) error
}
type Repository struct{ ReportRepository }

// NewRepository объединяет операции хранилища отчётов на основе пула db.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{ReportRepository: NewReportRepoStruct(db)}
}

// IsNotFound проверяет наличие pgx.ErrNoRows в цепочке e.
func IsNotFound(e error) bool { return errors.Is(e, pgx.ErrNoRows) }
