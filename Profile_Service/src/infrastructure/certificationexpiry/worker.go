package certificationexpiry

import (
	"context"
	"time"

	"go.uber.org/zap"
	"profile/models"
	"profile/src/core/service"
)

type Worker struct {
	service  service.CertificationService
	interval time.Duration
	batch    int32
	logger   *zap.Logger
}

func New(profileService service.CertificationService, interval time.Duration, batch int32, logger *zap.Logger) *Worker {
	if interval <= 0 {
		interval = time.Minute
	}
	if batch <= 0 {
		batch = 100
	}
	return &Worker{service: profileService, interval: interval, batch: batch, logger: logger}
}

func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		w.expire(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Worker) expire(ctx context.Context) {
	result, err := w.service.ExpireWorkProfileCertifications(ctx, &models.ExpireWorkProfileCertificationsInput{Limit: w.batch})
	if err != nil {
		if ctx.Err() == nil {
			w.logger.Error("certification expiry batch failed", zap.Error(err))
		}
		return
	}
	if len(result.ExpiredCertifications) > 0 {
		w.logger.Info("expired certifications", zap.Int("count", len(result.ExpiredCertifications)))
	}
}
