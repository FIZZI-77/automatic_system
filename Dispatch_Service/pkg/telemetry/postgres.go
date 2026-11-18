package telemetry

import (
	"context"
	"fmt"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPostgresPool создаёт пул pgx с трассировкой запросов и метриками соединений.
func NewPostgresPool(ctx context.Context, connectionString string, maxConnections int32) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(connectionString)

	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL connection string: %w", err)
	}

	config.ConnConfig.Tracer = otelpgx.NewTracer()

	if maxConnections > 0 {
		config.MaxConns = maxConnections
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)

	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL pool: %w", err)
	}

	if err := otelpgx.RecordStats(pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("record PostgreSQL pool metrics: %w", err)
	}

	return pool, nil
}
