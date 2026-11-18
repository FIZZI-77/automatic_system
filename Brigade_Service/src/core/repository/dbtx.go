package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Querier interface {
	// Exec выполняет SQL-команду и возвращает её результат или ошибку.
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	// Query выполняет SQL-запрос; вызывающий код закрывает возвращённые строки и проверяет Rows.Err.
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
	// QueryRow запрашивает одну строку; ошибка, включая отсутствие строки, возвращается из Scan.
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
}

type DBPools struct {
	Write *pgxpool.Pool
	Read  *pgxpool.Pool
}

// rollbackTx откатывает транзакцию с независимым от отмены ctx таймаутом 5 секунд;
// ошибки отката, включая уже завершённую транзакцию, игнорируются.
func rollbackTx(ctx context.Context, tx pgx.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	_ = tx.Rollback(rollbackCtx)
}

// rollbackTxOnCancel регистрирует откат при отмене ctx и возвращает функцию для defer.
// Она снимает обработчик и откатывает транзакцию либо ждёт уже начавшегося отката.
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
