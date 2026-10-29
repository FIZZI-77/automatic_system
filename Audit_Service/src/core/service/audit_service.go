package service

import (
	"audit/models"
	"audit/src/core/repository"
	"context"
	"github.com/google/uuid"
)

type AuditServiceStruct struct {
	writer repository.EntryWriterRepository
	reader repository.EntryReaderRepository
}

// NewAuditServiceStruct создаёт сервис аудита с отдельными зависимостями записи и чтения.
func NewAuditServiceStruct(repo *repository.Repository) *AuditServiceStruct {
	return &AuditServiceStruct{
		writer: repo.EntryWriterRepository,
		reader: repo.EntryReaderRepository,
	}
}

// Consume передаёт событие в хранилище аудита и возвращает ошибку его сохранения.
func (s *AuditServiceStruct) Consume(c context.Context, e models.Event) error {
	return s.writer.Store(c, e)
}

// Get возвращает запись аудита по ID, сохраняя ошибку хранилища при её отсутствии.
func (s *AuditServiceStruct) Get(c context.Context, id uuid.UUID) (*models.Entry, error) {
	return s.reader.Get(c, id)
}

// List возвращает страницу записей аудита по фильтрам и общее количество из хранилища.
func (s *AuditServiceStruct) List(c context.Context, f models.Filter) ([]*models.Entry, int64, error) {
	return s.reader.List(c, f)
}
