package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// Cleanup удаляет забытые загрузки и повторяет сохранённые удаления S3.
// Метаданные остаются скрытыми при любом сбое хранилища или подтверждения задачи.
func (s *Service) Cleanup(ctx context.Context) error {
	const batchSize = 100
	// Даём загрузке час после окончания срока подписи для завершения и подтверждения.
	if err := s.repo.ExpireUploads(ctx, time.Now().Add(-time.Hour), batchSize); err != nil {
		return err
	}
	jobs, err := s.repo.PendingDeletions(ctx, batchSize)
	if err != nil {
		return err
	}
	var cleanupErr error
	for _, job := range jobs {
		if err := s.store.Delete(ctx, job.ObjectKey); err != nil {
			retryErr := s.repo.RetryDeletion(ctx, job.FileID, err)
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("delete object %s: %w", job.FileID, err), retryErr)
			continue
		}
		cleanupErr = errors.Join(cleanupErr, s.repo.CompleteDeletion(ctx, job.FileID))
	}
	return cleanupErr
}

// RunCleanup обслуживает очередь до отмены ctx; вызывающий код ожидает завершения.
func (s *Service) RunCleanup(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		attemptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := s.Cleanup(attemptCtx)
		cancel()
		if err != nil && ctx.Err() == nil {
			s.logger.Warn("file cleanup incomplete; will retry", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
