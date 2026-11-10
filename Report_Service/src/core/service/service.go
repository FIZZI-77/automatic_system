package service

import (
	"context"
	"report/models"
	"report/src/core/repository"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AnalyticsSource interface {
	// Build получает табличные данные заданного типа отчёта с фильтром и ролями инициатора.
	Build(context.Context, models.Type, models.Filter, []string) ([][]string, error)
}
type FileStorage interface {
	// Upload загружает артефакт для отчёта от имени владельца с заданными ролями и возвращает ID файла.
	Upload(context.Context, uuid.UUID, uuid.UUID, []string, models.Artifact) (uuid.UUID, error)
	// Download возвращает ссылку и срок скачивания файла для пользователя с заданными ролями.
	Download(context.Context, uuid.UUID, uuid.UUID, []string) (string, time.Time, error)
}
type Generator interface {
	// Generate создаёт файловый артефакт заданного формата из имени отчёта и табличных строк.
	Generate(models.Format, string, [][]string) (models.Artifact, error)
}
type ReportService interface {
	// Create проверяет параметры и ставит задание отчёта в очередь генерации.
	Create(context.Context, models.CreateInput) (*models.Report, error)
	// Get возвращает отчёт инициатору либо привилегированному пользователю; иначе даёт ErrForbidden.
	Get(context.Context, uuid.UUID, uuid.UUID, bool) (*models.Report, error)
	// List возвращает страницу доступных заданий и общий счётчик, ограничивая обычного пользователя его отчётами.
	List(context.Context, uuid.UUID, bool, *models.Status, int32, int32) ([]*models.Report, int64, error)
	// Cancel отменяет доступный отчёт PENDING или FAILED; иной статус даёт ErrInvalidState.
	Cancel(context.Context, uuid.UUID, uuid.UUID, bool) (*models.Report, error)
	// Retry возвращает доступный FAILED-отчёт в очередь; иной статус даёт ErrInvalidState.
	Retry(context.Context, uuid.UUID, uuid.UUID, bool) (*models.Report, error)
	// Download возвращает ссылку скачивания доступного COMPLETED-отчёта с файлом.
	Download(context.Context, uuid.UUID, uuid.UUID, []string, bool) (models.Download, error)
}
type JobProcessor interface {
	// ProcessNext обрабатывает одно задание; bool сообщает о его захвате, пустая очередь даёт false, nil.
	ProcessNext(context.Context) (bool, error)
}
type Service struct {
	ReportService
	JobProcessor
}

// NewService объединяет API отчётов и фоновую обработку заданий с общими зависимостями.
// nil logger допускается и отключает вывод журнала.
func NewService(repo repository.ReportRepository, source AnalyticsSource, files FileStorage, generator Generator, logger *zap.Logger) *Service {
	impl := &ReportServiceStruct{repo: repo, source: source, files: files, generator: generator, logger: logger}
	return &Service{ReportService: impl, JobProcessor: impl}
}
