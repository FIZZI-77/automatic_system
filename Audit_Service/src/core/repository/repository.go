package repository

import (
	"audit/models"
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EntryWriterRepository interface {
	Store(context.Context, models.Event) error
}
type EntryReaderRepository interface {
	Get(context.Context, uuid.UUID) (*models.Entry, error)
	List(context.Context, models.Filter) ([]*models.Entry, int64, error)
}
type Repository struct {
	EntryWriterRepository
	EntryReaderRepository
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		EntryWriterRepository: NewEntryWriterRepoStruct(db),
		EntryReaderRepository: NewEntryReaderRepoStruct(db),
	}
}

func IsNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
