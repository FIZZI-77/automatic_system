package positionhistory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"location/models"
	"location/src/core/service"

	"go.uber.org/zap"
)

const (
	defaultBatchSize       = 500
	defaultFlushInterval   = 5 * time.Second
	defaultShutdownTimeout = 5 * time.Second
)

type BatchRepository interface {
	AppendPositionsBatch(ctx context.Context, positions []*models.Position) (int64, error)
}

type Config struct {
	BatchSize       int
	FlushInterval   time.Duration
	ShutdownTimeout time.Duration
}

type Worker struct {
	buffer service.PositionBuffer
	repo   BatchRepository
	cfg    Config
	log    *zap.Logger
	wake   chan struct{}
}

func New(
	buffer service.PositionBuffer,
	repo BatchRepository,
	cfg Config,
	logger *zap.Logger,
) (*Worker, error) {
	if buffer == nil {
		return nil, errors.New("position history worker: buffer is required")
	}
	if repo == nil {
		return nil, errors.New("position history worker: repository is required")
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushInterval
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = defaultShutdownTimeout
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Worker{
		buffer: buffer,
		repo:   repo,
		cfg:    cfg,
		log:    logger,
		wake:   make(chan struct{}, 1),
	}, nil
}

func (w *Worker) Add(position *models.Position) error {
	if err := w.buffer.Add(position); err != nil {
		return err
	}
	if w.buffer.Len() >= w.cfg.BatchSize {
		select {
		case w.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(
				context.WithoutCancel(ctx),
				w.cfg.ShutdownTimeout,
			)
			defer cancel()
			w.flushAll(shutdownCtx)
			return nil
		case <-ticker.C:
			w.flushAll(ctx)
		case <-w.wake:
			w.flushFullBatches(ctx)
		}
	}
}

func (w *Worker) flushFullBatches(ctx context.Context) {
	for w.buffer.Len() >= w.cfg.BatchSize && ctx.Err() == nil {
		w.flush(ctx, w.cfg.BatchSize)
	}
}

func (w *Worker) flushAll(ctx context.Context) {
	for w.buffer.Len() > 0 && ctx.Err() == nil {
		w.flush(ctx, w.cfg.BatchSize)
	}
}

func (w *Worker) flush(ctx context.Context, maxSize int) {
	batch := w.buffer.TakeBatch(maxSize)
	if len(batch) == 0 {
		return
	}
	written, err := w.repo.AppendPositionsBatch(ctx, batch)
	if err != nil {
		w.buffer.Prepend(batch)
		w.log.Error(
			"position history batch write failed; batch returned to buffer",
			zap.Int("batch_size", len(batch)),
			zap.Error(err),
		)
		return
	}
	if written != int64(len(batch)) {
		remaining := int(written)
		if remaining < 0 {
			remaining = 0
		}
		if remaining > len(batch) {
			remaining = len(batch)
		}
		w.buffer.Prepend(batch[remaining:])
		w.log.Warn(
			"position history batch partially written",
			zap.Int("batch_size", len(batch)),
			zap.Int64("written", written),
		)
	}
}

func (w *Worker) String() string {
	return fmt.Sprintf(
		"position-history-worker(batch=%d, interval=%s)",
		w.cfg.BatchSize,
		w.cfg.FlushInterval,
	)
}
