package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Querier interface {
	// Exec выполняет SQL-команду без набора строк и возвращает результат выполнения.
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	// Query выполняет SQL-запрос; вызывающий код обязан закрыть возвращённые Rows.
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
	// QueryRow выполняет запрос одной строки; ошибка чтения возвращается при Scan.
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
}

type DBPools struct {
	Write *pgxpool.Pool
	Read  *pgxpool.Pool
}

type commandTxContextKey struct{}

type borrowedTx struct{ pgx.Tx }

// Commit возвращает nil без фиксации: заимствованной транзакцией управляет её владелец.
func (tx borrowedTx) Commit(context.Context) error { return nil }

// Rollback возвращает nil без отката: заимствованной транзакцией управляет её владелец.
func (tx borrowedTx) Rollback(context.Context) error { return nil }

// contextWithCommandTx возвращает дочерний контекст с транзакцией команд для вложенных операций.
func contextWithCommandTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, commandTxContextKey{}, tx)
}

// beginCommandTx заимствует транзакцию из ctx с пустыми Commit и Rollback
// либо начинает новую в pool. Владелец внешней транзакции сохраняет управление её завершением.
func beginCommandTx(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {

	if tx, ok := ctx.Value(commandTxContextKey{}).(pgx.Tx); ok && tx != nil {
		return borrowedTx{Tx: tx}, nil
	}

	return pool.Begin(ctx)
}

// rollbackTx пытается откатить tx с независимым от отмены ctx тайм-аутом пять секунд.
// Значения контекста сохраняет, ошибку отката игнорирует.
func rollbackTx(ctx context.Context, tx pgx.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	_ = tx.Rollback(rollbackCtx)
}

// rollbackTxOnCancel запускает откат при отмене ctx и возвращает функцию для defer.
// Она выполняет откат сама либо ждёт уже запущенный, исключая параллельный Rollback.
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
