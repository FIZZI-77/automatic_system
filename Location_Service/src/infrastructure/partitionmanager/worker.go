package partitionmanager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

const (
	defaultInterval    = 24 * time.Hour
	defaultMonthsAhead = 3
)

type Config struct {
	Interval    time.Duration
	MonthsAhead int
}

type Worker struct {
	db     *pgxpool.Pool
	cfg    Config
	logger *zap.Logger
}

func New(db *pgxpool.Pool, cfg Config, logger *zap.Logger) (*Worker, error) {
	if db == nil {
		return nil, errors.New("partition manager: database is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.MonthsAhead <= 0 {
		cfg.MonthsAhead = defaultMonthsAhead
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Worker{db: db, cfg: cfg, logger: logger}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()

	for {
		if err := w.ensure(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Error("position history partition maintenance failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (w *Worker) ensure(ctx context.Context) error {
	var created int
	if err := w.db.QueryRow(
		ctx,
		"SELECT ensure_position_history_partitions($1)",
		w.cfg.MonthsAhead,
	).Scan(&created); err != nil {
		return fmt.Errorf("ensure position history partitions: %w", err)
	}
	if created > 0 {
		w.logger.Info("position history partitions created", zap.Int("count", created))
	}
	return nil
}
