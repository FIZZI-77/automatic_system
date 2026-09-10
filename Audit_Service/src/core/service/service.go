package service

import (
	"audit/models"
	"audit/src/core/repository"
	"context"
	"github.com/google/uuid"
)

type AuditService interface {
	Consume(context.Context, models.Event) error
	Get(context.Context, uuid.UUID) (*models.Entry, error)
	List(context.Context, models.Filter) ([]*models.Entry, int64, error)
}
type Service struct{ AuditService }

func NewService(repo *repository.Repository) *Service {
	return &Service{AuditService: NewAuditServiceStruct(repo)}
}
func IsNotFound(err error) bool {
	return repository.IsNotFound(err)
}
