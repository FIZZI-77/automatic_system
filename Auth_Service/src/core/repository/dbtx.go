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

type borrowedTx struct{ pgx.Tx }

func (tx borrowedTx) Commit(context.Context) error   { return nil }
func (tx borrowedTx) Rollback(context.Context) error { return nil }

type commandTxContextKey struct{}

func contextWithCommandTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, commandTxContextKey{}, tx)
}

func commandExec(ctx context.Context, fallback DBTX) DBTX {
	if tx, ok := ctx.Value(commandTxContextKey{}).(pgx.Tx); ok && tx != nil {
		return tx
	}
	return fallback
}

func beginNestedAware(ctx context.Context, exec DBTX) (pgx.Tx, error) {
	if tx, ok := ctx.Value(commandTxContextKey{}).(pgx.Tx); ok && tx != nil {
		return borrowedTx{Tx: tx}, nil
	}
	if tx, ok := exec.(pgx.Tx); ok {
		return borrowedTx{Tx: tx}, nil
	}
	pool, ok := exec.(*pgxpool.Pool)
	if !ok {
		return nil, fmt.Errorf("repository: transaction source is unavailable")
	}
	return pool.Begin(ctx)
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
	if tx, ok := ctx.Value(commandTxContextKey{}).(pgx.Tx); ok && tx != nil {
		return fn(tx)
	}
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
