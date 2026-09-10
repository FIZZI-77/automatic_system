package pkg

import (
	"context"
	"fmt"
	"profile/pkg/telemetry"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	Host     string
	Port     string
	Username string
	Password string
	DbName   string
	SSLMode  string
}

func NewPostgresDB(cfg Config) (*pgxpool.Pool, error) {
	connString := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.Username, cfg.DbName, cfg.Password, cfg.SSLMode)

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
