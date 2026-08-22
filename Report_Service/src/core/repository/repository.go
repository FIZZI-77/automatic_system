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
	Create(context.Context, models.CreateInput) (*models.Report, error)
	Get(context.Context, uuid.UUID) (*models.Report, error)
	List(context.Context, models.ListFilter) ([]*models.Report, int64, error)
	Cancel(context.Context, uuid.UUID) (*models.Report, error)
	Retry(context.Context, uuid.UUID) (*models.Report, error)
	Claim(context.Context) (*models.Report, error)
	Complete(context.Context, uuid.UUID, uuid.UUID) error
	Fail(context.Context, uuid.UUID, string) error
}
type Repository struct{ ReportRepository }

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{ReportRepository: NewReportRepoStruct(db)}
}
func IsNotFound(e error) bool { return errors.Is(e, pgx.ErrNoRows) }
