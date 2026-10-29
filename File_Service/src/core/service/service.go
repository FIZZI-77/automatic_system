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
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

const MaxFileSize int64 = 25 << 20

var allowedTypes = map[string]bool{
	"image/jpeg":      true,
	"image/png":       true,
	"image/gif":       true,
	"image/webp":      true,
	"application/pdf": true,
	"text/csv":        true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": true,
}

type Service struct {
	repo   *repository.Repository
	store  objectStorage
	ttl    time.Duration
	logger *zap.Logger
}

// New создаёт сервис файлов с хранилищем метаданных, S3 и сроком действия подписанных ссылок ttl.
func New(repo *repository.Repository, store objectStorage, ttl time.Duration, logger *zap.Logger) *Service {
	return &Service{
		repo:   repo,
		store:  store,
		ttl:    ttl,
		logger: logger,
	}
}

// Create проверяет владельца, имя, MIME-тип и размер файла до 25 МиБ, сохраняет
// метаданные и выдаёт подписанную ссылку загрузки. Подписывает URL до записи в БД;
// незавершённые загрузки затем удаляются фоновой очисткой.
func (s *Service) Create(ctx context.Context, in models.CreateInput) (*models.PresignedFile, error) {
	logger := s.logger.With(pkg.RequestIDField(ctx), zap.String("operation", "create_upload"))
	in.Name = filepath.Base(strings.TrimSpace(in.Name))
	in.ContentType = strings.ToLower(strings.TrimSpace(in.ContentType))

	if in.OwnerUserID == uuid.Nil || in.Name == "." || in.Name == "" || in.Size <= 0 || in.Size > MaxFileSize || !allowedTypes[in.ContentType] {
		return nil, fmt.Errorf("%w: invalid file metadata", models.ErrValidation)
	}

	id := uuid.New()
	key := fmt.Sprintf("%s/%s/%s", in.OwnerUserID, id, in.Name)
	in.UploadExpiresAt = time.Now().Add(s.ttl)
	u, err := s.store.UploadURL(ctx, key, in.ContentType, in.Checksum, in.Size, s.ttl)

	if err != nil {
		logger.Error("presign upload failed", zap.Error(err))
		return nil, err
	}

	f, err := s.repo.Create(ctx, in, key)

	if err != nil {
		logger.Error("file metadata creation failed", zap.Error(err))
		return nil, err
	}

	logger.Info("upload prepared", zap.String("file_id", f.ID.String()), zap.String("content_type", f.ContentType), zap.Int64("size", f.Size))
	return &models.PresignedFile{
		File:      f,
		URL:       u,
		ExpiresAt: in.UploadExpiresAt,
	}, nil
}

// Confirm сверяет размер и MIME-тип объекта в S3 и подтверждает загрузку для
// владельца или привилегированного пользователя. При несовпадении пытается поместить
// ожидающий файл в карантин и возвращает ошибку; ошибки карантина записывает в журнал.
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

// Link связывает загруженный файл с ресурсом для владельца или привилегированного
// пользователя. Требует непустой тип ресурса и ненулевой ID; ограничения статуса проверяет хранилище.
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

	return s.repo.Link(ctx, id, in)
}

// Download выдаёт подписанную ссылку скачивания файла UPLOADED или LINKED
// владельцу или привилегированному пользователю; иной статус даёт ErrValidation.
func (s *Service) Download(ctx context.Context, id, actor uuid.UUID, privileged bool) (*models.PresignedFile, error) {
	f, err := s.repo.Get(ctx, id)

	if err != nil {
		return nil, err
	}

	if f.OwnerUserID != actor && !privileged {
		return nil, models.ErrPermissionDenied
	}

	if !downloadable(f.Status) {
		return nil, models.ErrValidation
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

// downloadable сообщает, разрешает ли статус скачивание: UPLOADED или LINKED.
func downloadable(status models.Status) bool {
	return status == models.StatusUploaded || status == models.StatusLinked
}

// Delete проверяет права, помечает метаданные удалёнными и ставит объект
// в постоянную очередь очистки S3.
func (s *Service) Delete(ctx context.Context, id, actor uuid.UUID, privileged bool) error {
	f, err := s.repo.GetForDeletion(ctx, id)

	if err != nil {
		return err
	}

	if f.OwnerUserID != actor && !privileged {
		return models.ErrPermissionDenied
	}

	if err = s.repo.QueueDeletion(ctx, id); err != nil {
		return err
	}
	return nil
}

// List возвращает связанные файлы ресурса, ограничивая обычного пользователя его файлами.
func (s *Service) List(ctx context.Context, typ string, id, actor uuid.UUID, privileged bool) ([]*models.File, error) {
	files, err := s.repo.List(ctx, typ, id)

	if err != nil {
		return nil, err
	}

	if privileged {
		return files, nil
	}

	visible := make([]*models.File, 0, len(files))
	for _, file := range files {
		if file.OwnerUserID == actor {
			visible = append(visible, file)
		}
	}
	return visible, nil
}

// IsNotFound проверяет наличие pgx.ErrNoRows в цепочке err.
func IsNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
