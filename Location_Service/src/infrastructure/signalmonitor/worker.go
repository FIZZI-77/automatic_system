package signalmonitor

import (
	"context"
	"time"

	"location/models"

	"go.uber.org/zap"
)

type Detector interface {
	DetectLostSignals(
		context.Context,
		*models.DetectLostSignalsInput,
	) (*models.DetectLostSignalsResult, error)
}
type Config struct {
	Interval, StaleAfter, OfflineAfter time.Duration
	BatchSize                          int32
}
type Worker struct {
	detector Detector
	cfg      Config
	log      *zap.Logger
}

func New(detector Detector, cfg Config, logger *zap.Logger) *Worker {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = 15 * time.Second
	}
	if cfg.OfflineAfter <= cfg.StaleAfter {
		cfg.OfflineAfter = 60 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Worker{detector: detector, cfg: cfg, log: logger}
}
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			result, err := w.detector.DetectLostSignals(
				ctx,
				&models.DetectLostSignalsInput{
					StaleBefore:   now.Add(-w.cfg.StaleAfter),
					OfflineBefore: now.Add(-w.cfg.OfflineAfter),
					Limit:         w.cfg.BatchSize,
				},
			)
			if err != nil {
				w.log.Error("detect lost signals", zap.Error(err))
				continue
			}
			if len(result.Changes) > 0 {
				w.log.Info("signal statuses changed", zap.Int("count", len(result.Changes)))
			}
		}
	}
}
