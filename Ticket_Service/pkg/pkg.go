package pkg

import (
	"context"
	"fmt"
	"strings"
	"ticket/pkg/telemetry"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	Host     string
	Port     string
	Username string
	Password string
	DbName   string
	SSLMode  string
	MaxConns int32
	MinConns int32
}

func NewPostgresDB(cfg Config) (*pgxpool.Pool, error) {
	connString := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.Username, cfg.DbName, cfg.Password, cfg.SSLMode)

	poolSettings := make([]string, 0, 2)
	if cfg.MaxConns > 0 {
		poolSettings = append(poolSettings, fmt.Sprintf("pool_max_conns=%d", cfg.MaxConns))
	}
	if cfg.MinConns > 0 {
		poolSettings = append(poolSettings, fmt.Sprintf("pool_min_conns=%d", cfg.MinConns))
	}
	if len(poolSettings) > 0 {
		connString += " " + strings.Join(poolSettings, " ")
	}

	db, err := telemetry.NewPostgresPool(context.Background(), connString)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
