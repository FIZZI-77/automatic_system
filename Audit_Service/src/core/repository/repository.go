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
	// Store сохраняет событие с маскировкой чувствительных полей; повтор пары топик–ID пропускает.
	Store(context.Context, models.Event) error
}
type EntryReaderRepository interface {
	// Get возвращает запись аудита по ID либо pgx.ErrNoRows при отсутствии.
	Get(context.Context, uuid.UUID) (*models.Entry, error)
	// List возвращает страницу аудита от новых событий к старым и общий счётчик.
	// На пустой странице счётчик равен нулю; некорректный лимит заменяется на 50.
	List(context.Context, models.Filter) ([]*models.Entry, int64, error)
}
type Repository struct {
	EntryWriterRepository
	EntryReaderRepository
}

// NewRepository объединяет запись и чтение аудита с общим пулом PostgreSQL.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		EntryWriterRepository: NewEntryWriterRepoStruct(db),
		EntryReaderRepository: NewEntryReaderRepoStruct(db),
	}
}

// IsNotFound проверяет наличие pgx.ErrNoRows в цепочке err.
func IsNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
