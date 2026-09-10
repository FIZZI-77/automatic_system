package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Querier interface {
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
}

type DBPools struct {
	Write *pgxpool.Pool
	Read  *pgxpool.Pool
}

type commandTxContextKey struct{}

type borrowedTx struct{ pgx.Tx }

func (tx borrowedTx) Commit(context.Context) error   { return nil }
func (tx borrowedTx) Rollback(context.Context) error { return nil }

func contextWithCommandTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, commandTxContextKey{}, tx)
}

func beginCommandTx(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	if tx, ok := ctx.Value(commandTxContextKey{}).(pgx.Tx); ok && tx != nil {
		return borrowedTx{Tx: tx}, nil
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
