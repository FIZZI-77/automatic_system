package repository

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"profile/models"
)

// mapDatabaseError добавляет имя операции и переводит ошибки отсутствия, уникальности,
// внешнего ключа и некорректных данных в доменные ошибки. Прочие ошибки оборачивает,
// nil возвращает без изменений.
func mapDatabaseError(operation string, err error) error {

	if err == nil {
		return nil
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("repository: %s: %w", operation, models.ErrNotFound)
	}

	var pgErr *pgconn.PgError

	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return fmt.Errorf("repository: %s: %w", operation, models.ErrAlreadyExists)
		case "23503":
			return fmt.Errorf("repository: %s: %w", operation, models.ErrNotFound)
		case "23502", "23514", "22001", "22P02":
			return fmt.Errorf("repository: %s: %w", operation, models.ErrValidation)
		}
	}

	return fmt.Errorf("repository: %s: %w", operation, err)
}

// sortOrderSQL возвращает ASC только для SortOrderAsc, иначе — DESC.
func sortOrderSQL(order models.SortOrder) string {

	if order == models.SortOrderAsc {
		return "ASC"
	}

	return "DESC"
}
