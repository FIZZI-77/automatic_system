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

func NewAuditServiceStruct(repo *repository.Repository) *AuditServiceStruct {
	return &AuditServiceStruct{writer: repo.EntryWriterRepository, reader: repo.EntryReaderRepository}
}
func (s *AuditServiceStruct) Consume(c context.Context, e models.Event) error {
	return s.writer.Store(c, e)
}
func (s *AuditServiceStruct) Get(c context.Context, id uuid.UUID) (*models.Entry, error) {
	return s.reader.Get(c, id)
}
func (s *AuditServiceStruct) List(c context.Context, f models.Filter) ([]*models.Entry, int64, error) {
	return s.reader.List(c, f)
}
