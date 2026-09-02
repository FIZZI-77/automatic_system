package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"file/models"
	"file/pkg"
	"file/src/core/repository"
	"file/src/infrastructure/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

const MaxFileSize int64 = 25 << 20

var allowedTypes = map[string]bool{"image/jpeg": true, "image/png": true, "image/gif": true, "image/webp": true, "application/pdf": true, "text/csv": true, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": true}

type Service struct {
	repo   *repository.Repository
	store  *storage.S3
	ttl    time.Duration
	logger *zap.Logger
}

func New(repo *repository.Repository, store *storage.S3, ttl time.Duration, logger *zap.Logger) *Service {
	return &Service{
		repo:   repo,
		store:  store,
		ttl:    ttl,
		logger: logger,
	}
}

func (s *Service) Create(ctx context.Context, in models.CreateInput) (*models.PresignedFile, error) {
	logger := s.logger.With(pkg.RequestIDField(ctx), zap.String("operation", "create_upload"))
	in.Name = filepath.Base(strings.TrimSpace(in.Name))
	in.ContentType = strings.ToLower(strings.TrimSpace(in.ContentType))
	if in.OwnerUserID == uuid.Nil || in.Name == "." || in.Name == "" || in.Size <= 0 || in.Size > MaxFileSize || !allowedTypes[in.ContentType] {
		return nil, fmt.Errorf("%w: invalid file metadata", models.ErrValidation)
	}
	id := uuid.New()
	key := fmt.Sprintf("%s/%s/%s", in.OwnerUserID, id, in.Name)
	f, err := s.repo.Create(ctx, in, key)
	if err != nil {
		logger.Error("file metadata creation failed", zap.Error(err))
		return nil, err
	}
	u, err := s.store.UploadURL(ctx, key, in.ContentType, in.Checksum, s.ttl)
	if err != nil {
		logger.Error("presign upload failed", zap.String("file_id", f.ID.String()), zap.Error(err))
		return nil, err
	}
	logger.Info("upload prepared", zap.String("file_id", f.ID.String()), zap.String("content_type", f.ContentType), zap.Int64("size", f.Size))
	return &models.PresignedFile{
		File:      f,
		URL:       u,
		ExpiresAt: time.Now().Add(s.ttl),
	}, nil
}

func (s *Service) Confirm(ctx context.Context, id, actor uuid.UUID, privileged bool) (*models.File, error) {
	logger := s.logger.With(pkg.RequestIDField(ctx), zap.String("operation", "confirm_upload"), zap.String("file_id", id.String()))
	f, err := s.repo.Get(ctx, id)

	if err != nil {
		return nil, err
	}

	if f.OwnerUserID != actor && !privileged {
		return nil, models.ErrPermissionDenied
	}

	size, typ, err := s.store.Stat(ctx, f.ObjectKey)
	if err != nil {
		return nil, err
	}

	if size != f.Size || typ != f.ContentType {
		logger.Warn("uploaded object metadata mismatch", zap.Int64("expected_size", f.Size), zap.Int64("actual_size", size), zap.String("expected_content_type", f.ContentType), zap.String("actual_content_type", typ))
		if quarantineErr := s.repo.Quarantine(ctx, id); quarantineErr != nil {
			logger.Error("failed to quarantine upload", zap.Error(quarantineErr))
		}
		return nil, errors.New("uploaded object metadata mismatch")
	}
	confirmed, err := s.repo.Confirm(ctx, id)
	if err == nil {
		logger.Info("upload confirmed")
	}
	return confirmed, err
}
func (s *Service) Link(ctx context.Context, id, actor uuid.UUID, privileged bool, in models.LinkInput) (*models.File, error) {
	if in.ResourceID == uuid.Nil || strings.TrimSpace(in.ResourceType) == "" {
		return nil, fmt.Errorf("%w: invalid resource", models.ErrValidation)
	}
	f, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if f.OwnerUserID != actor && !privileged {
		return nil, models.ErrPermissionDenied
	}
	folder := strings.Map(func(value rune) rune {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-' || value == '_' {
			return value
		}
		return '-'
	}, strings.ToLower(strings.TrimSpace(in.ResourceType)))
	targetKey := fmt.Sprintf("%s/%s/%s-%s", folder, in.ResourceID, f.ID, f.Name)
	if f.ObjectKey == targetKey {
		return s.repo.Link(ctx, id, in, targetKey)
	}
	if err := s.store.Move(ctx, f.ObjectKey, targetKey); err != nil {
		return nil, err
	}
	linked, err := s.repo.Link(ctx, id, in, targetKey)
	if err != nil {
		_ = s.store.Move(ctx, targetKey, f.ObjectKey)
		return nil, err
	}
	return linked, nil
}
func (s *Service) Download(ctx context.Context, id, actor uuid.UUID, privileged bool) (*models.PresignedFile, error) {
	f, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if f.OwnerUserID != actor && !privileged {
		return nil, models.ErrPermissionDenied
	}
	u, err := s.store.DownloadURL(ctx, f.ObjectKey, f.Name, s.ttl)
	if err != nil {
		return nil, err
	}
	return &models.PresignedFile{
		File:      f,
		URL:       u,
		ExpiresAt: time.Now().Add(s.ttl),
	}, nil
}
func (s *Service) Delete(ctx context.Context, id, actor uuid.UUID, privileged bool) error {
	f, err := s.repo.Get(ctx, id)
	if err != nil {
		return err
	}
	if f.OwnerUserID != actor && !privileged {
		return models.ErrPermissionDenied
	}
	if err = s.store.Delete(ctx, f.ObjectKey); err != nil {
		return err
	}
	return s.repo.Delete(ctx, id)
}
func (s *Service) List(ctx context.Context, typ string, id, actor uuid.UUID, privileged bool) ([]*models.File, error) {
	files, err := s.repo.List(ctx, typ, id)
	if err != nil {
		return nil, err
	}
	if privileged {
		return files, nil
	}
	for _, file := range files {
		if file.OwnerUserID != actor {
			return nil, models.ErrPermissionDenied
		}
	}
	return files, nil
}

func IsNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
