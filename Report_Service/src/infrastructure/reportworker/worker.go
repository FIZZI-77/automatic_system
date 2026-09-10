package reportworker

import (
	"context"
	"go.uber.org/zap"
	"report/src/core/service"
	"time"
)

type Worker struct {
	processor service.JobProcessor
	log       *zap.Logger
	interval  time.Duration
}

func New(p service.JobProcessor, l *zap.Logger, d time.Duration) *Worker {
	return &Worker{processor: p, log: l, interval: d}
}
func (w *Worker) Run(ctx context.Context) error {
	tick := time.NewTicker(w.interval)
	defer tick.Stop()
	for {
		processed, e := w.processor.ProcessNext(ctx)
		if e != nil && ctx.Err() == nil {
			w.log.Error("report job failed", zap.Error(e))
		}
		if processed {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
