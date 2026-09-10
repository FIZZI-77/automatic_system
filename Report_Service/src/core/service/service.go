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
	Build(context.Context, models.Type, models.Filter, []string) ([][]string, error)
}
type FileStorage interface {
	Upload(context.Context, uuid.UUID, uuid.UUID, []string, models.Artifact) (uuid.UUID, error)
	Download(context.Context, uuid.UUID, uuid.UUID, []string) (string, time.Time, error)
}
type Generator interface {
	Generate(models.Format, string, [][]string) (models.Artifact, error)
}
type ReportService interface {
	Create(context.Context, models.CreateInput) (*models.Report, error)
	Get(context.Context, uuid.UUID, uuid.UUID, bool) (*models.Report, error)
	List(context.Context, uuid.UUID, bool, *models.Status, int32, int32) ([]*models.Report, int64, error)
	Cancel(context.Context, uuid.UUID, uuid.UUID, bool) (*models.Report, error)
	Retry(context.Context, uuid.UUID, uuid.UUID, bool) (*models.Report, error)
	Download(context.Context, uuid.UUID, uuid.UUID, []string, bool) (models.Download, error)
}
type JobProcessor interface {
	ProcessNext(context.Context) (bool, error)
}
type Service struct {
	ReportService
	JobProcessor
}

func NewService(repo repository.ReportRepository, source AnalyticsSource, files FileStorage, generator Generator, logger *zap.Logger) *Service {
	impl := &ReportServiceStruct{repo: repo, source: source, files: files, generator: generator, logger: logger}
	return &Service{ReportService: impl, JobProcessor: impl}
}
