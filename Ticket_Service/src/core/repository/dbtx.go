package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Querier interface {
	// Exec выполняет SQL-команду без набора строк и возвращает тег результата.
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	// Query выполняет SQL-запрос с набором строк; вызывающий обязан закрыть Rows.
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
	// QueryRow запрашивает одну строку; ошибки запроса возвращаются при вызове Scan.
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
}

type DBPools struct {
	Write *pgxpool.Pool
	Read  *pgxpool.Pool
}

type commandTxContextKey struct{}

type borrowedTx struct{ pgx.Tx }

// Commit оставляет фиксацию владельцу внешней транзакции и возвращает nil.
func (tx borrowedTx) Commit(context.Context) error { return nil }

// Rollback оставляет откат владельцу внешней транзакции и возвращает nil.
func (tx borrowedTx) Rollback(context.Context) error { return nil }

// contextWithCommandTx добавляет транзакцию в контекст для использования вложенными командами.
func contextWithCommandTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, commandTxContextKey{}, tx)
}

// beginCommandTx заимствует транзакцию из ctx либо начинает новую через pool.
// Для заимствованной транзакции Commit и Rollback ничего не завершают.
func beginCommandTx(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {

	if tx, ok := ctx.Value(commandTxContextKey{}).(pgx.Tx); ok && tx != nil {
		return borrowedTx{Tx: tx}, nil
	}

	return pool.Begin(ctx)
}

// rollbackTx пытается откатить транзакцию с независимым от отмены ctx таймаутом пять секунд.
// Ошибку отката игнорирует, в том числе для уже завершённой транзакции.
func rollbackTx(ctx context.Context, tx pgx.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	_ = tx.Rollback(rollbackCtx)
}

// rollbackTxOnCancel планирует откат при отмене ctx и возвращает функцию завершения.
// Её следует вызвать через defer: она выполняет откат либо ожидает уже начатый.
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
