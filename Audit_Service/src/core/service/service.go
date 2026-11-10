package service

import (
	"audit/models"
	"audit/src/core/repository"
	"context"
	"github.com/google/uuid"
)

type AuditService interface {
	// Consume сохраняет событие в журнале аудита с исключением повторов по топику и ID события.
	Consume(context.Context, models.Event) error
	// Get возвращает запись аудита по ID либо ошибку отсутствия записи.
	Get(context.Context, uuid.UUID) (*models.Entry, error)
	// List возвращает страницу журнала по фильтрам и общий счётчик; на пустой странице счётчик равен нулю.
	List(context.Context, models.Filter) ([]*models.Entry, int64, error)
}
type Service struct{ AuditService }

// NewService объединяет операции сервиса аудита на основе repo.
func NewService(repo *repository.Repository) *Service {
	return &Service{AuditService: NewAuditServiceStruct(repo)}
}

// IsNotFound сообщает, содержит ли цепочка err ошибку отсутствия записи в хранилище аудита.
func IsNotFound(err error) bool {
	return repository.IsNotFound(err)
}
