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
