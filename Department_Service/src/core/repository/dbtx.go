package repository

import (
	"context"
	"database/sql"
	"fmt"
)

type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func withTransaction(ctx context.Context, exec DBTX, operation string, fn func(txExec DBTX) error) error {
	if tx, ok := exec.(*sql.Tx); ok {
		return fn(tx)
	}

	db, ok := exec.(*sql.DB)
	if !ok {
		return fmt.Errorf("repository: %s: transaction source is unavailable", operation)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("repository: %s: begin tx: %w", operation, err)
	}
	defer tx.Rollback()

	if err = fn(tx); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("repository: %s: commit: %w", operation, err)
	}

	return nil
}
