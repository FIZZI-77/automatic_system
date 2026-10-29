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
	// Exec выполняет SQL-команду и возвращает тег с количеством затронутых строк.
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	// Query возвращает набор строк; вызывающий обязан закрыть Rows после чтения.
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
	// QueryRow запрашивает одну строку; ошибки запроса возвращаются при Scan.
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
}

type DBPools struct {
	Write *pgxpool.Pool
	Read  *pgxpool.Pool
}

type borrowedTx struct {
	pgx.Tx
}

// Commit оставляет фиксацию владельцу заимствованной транзакции и возвращает nil.
func (tx borrowedTx) Commit(context.Context) error {
	return nil
}

// Rollback оставляет откат владельцу заимствованной транзакции и возвращает nil.
func (tx borrowedTx) Rollback(context.Context) error {
	return nil
}

type commandTxContextKey struct {
}

// contextWithCommandTx сохраняет транзакцию в ctx для общих вложенных команд.
func contextWithCommandTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, commandTxContextKey{}, tx)
}

// commandExec выбирает транзакцию из ctx либо возвращает резервный исполнитель fallback.
func commandExec(ctx context.Context, fallback DBTX) DBTX {

	if tx, ok := ctx.Value(commandTxContextKey{}).(pgx.Tx); ok && tx != nil {
		return tx
	}

	return fallback
}

// beginNestedAware заимствует транзакцию из ctx или exec либо начинает новую через пул.
// Заимствованную транзакцию завершает её владелец; неподдерживаемый exec вызывает ошибку.
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

// rollbackTx пытается откатить транзакцию с независимым от отмены ctx таймаутом пять секунд.
// Ошибку отката, включая уже завершённую транзакцию, игнорирует.
func rollbackTx(ctx context.Context, tx pgx.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(rollbackCtx)
}

// rollbackTxOnCancel назначает откат при отмене ctx и возвращает функцию завершения.
// Её следует вызвать через defer: она выполнит откат либо дождётся уже начатого.
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

// withTransaction вызывает fn в существующей транзакции либо начинает и фиксирует новую.
// Внешнюю транзакцию не завершает; ошибку fn возвращает с откатом собственной транзакции.
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
