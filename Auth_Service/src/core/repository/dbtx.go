package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DBTX interface {
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
}

type DBPools struct {
	Write *pgxpool.Pool
	Read  *pgxpool.Pool
}

func rollbackTx(ctx context.Context, tx pgx.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(rollbackCtx)
}

func rollbackTxOnCancel(ctx context.Context, tx pgx.Tx) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		rollbackTx(ctx, tx)
	})
	return func() {
		if stop() {
			rollbackTx(ctx, tx)
			return
		}
		<-done
	}
}

func withTransaction(ctx context.Context, exec DBTX, operation string, fn func(txExec DBTX) error) error {
	if tx, ok := exec.(pgx.Tx); ok {
		return fn(tx)
	}
	pool, ok := exec.(*pgxpool.Pool)
	if !ok {
		return fmt.Errorf("repository: %s: transaction source is unavailable", operation)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("repository: %s: begin tx: %w", operation, err)
	}
	defer rollbackTxOnCancel(ctx, tx)()
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("repository: %s: commit: %w", operation, err)
	}
	return nil
}
