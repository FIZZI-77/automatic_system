package service

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"sla/models"
	"sla/src/core/repository"
	"time"
)

type Service struct{ repo *repository.Repository }

// New создаёт сервис правил и контроля SLA с хранилищем r.
func New(r *repository.Repository) *Service { return &Service{repo: r} }

// CreateRule проверяет правило и сохраняет его; хранилище заполняет ID,
// активность и временные метки в переданном v.
func (s *Service) CreateRule(c context.Context, v *models.Rule) (*models.Rule, error) {

	if e := v.Validate(); e != nil {
		return nil, e
	}

	return s.repo.CreateRule(c, v)
}

// GetRule возвращает правило по ID, включая неактивное, либо ErrNotFound.
func (s *Service) GetRule(c context.Context, id uuid.UUID) (*models.Rule, error) {
	return s.repo.GetRule(c, id)
}

// UpdateRule проверяет и полностью обновляет правило по v.ID.
// Хранилище записывает актуальные временные метки в v; отсутствие даёт ErrNotFound.
func (s *Service) UpdateRule(c context.Context, v *models.Rule) (*models.Rule, error) {

	if e := v.Validate(); e != nil {
		return nil, e
	}

	return s.repo.UpdateRule(c, v)
}

// DeleteRule деактивирует правило без удаления строки и возвращает обновлённое правило.
func (s *Service) DeleteRule(c context.Context, id uuid.UUID) (*models.Rule, error) {
	return s.repo.DeleteRule(c, id)
}

// ListRules возвращает страницу правил по фильтрам и общий счётчик хранилища.
// На пустой странице счётчик равен нулю.
func (s *Service) ListRules(c context.Context, f models.RuleFilter) ([]*models.Rule, int64, error) {
	return s.repo.ListRules(c, f)
}

// GetTicketSLA возвращает состояние SLA по ID заявки либо ErrNotFound.
func (s *Service) GetTicketSLA(c context.Context, id uuid.UUID) (*models.TicketSLA, error) {
	return s.repo.GetTicketSLA(c, id)
}

// ListSLAs возвращает страницу состояний SLA по фильтрам и общий счётчик,
// равный нулю на пустой странице.
func (s *Service) ListSLAs(c context.Context, f models.SLAFilter) ([]*models.TicketSLA, int64, error) {
	return s.repo.ListSLAs(c, f)
}

// ListHistory возвращает страницу истории SLA заявки от новых событий к старым
// и общий счётчик, равный нулю на пустой странице.
func (s *Service) ListHistory(c context.Context, id uuid.UUID, l, o int32) ([]*models.History, int64, error) {
	return s.repo.ListHistory(c, id, l, o)
}

// Consume проверяет ID события и заявки, при достаточных атрибутах подбирает правило
// и передаёт событие для идемпотентного изменения SLA. Ошибку подбора возвращает
// без обработки события, в том числе если подходящего правила нет.
func (s *Service) Consume(c context.Context, e models.TicketEvent) error {

	if e.EventID == "" || e.TicketID == uuid.Nil {
		return fmt.Errorf("%w: invalid ticket event", models.ErrInvalidArgument)
	}

	var rule *models.Rule

	if e.DepartmentID != uuid.Nil && e.CategoryID != uuid.Nil && e.Priority.Valid() {
		var err error
		rule, err = s.repo.MatchRule(c, e.DepartmentID, e.CategoryID, e.Priority)

		if err != nil {
			return err
		}

	}

	return s.repo.ApplyEvent(c, e, rule)
}

// CheckDeadlines фиксирует предупреждения и нарушения сроков активных SLA на момент now.
// Запись истории и событий outbox выполняется хранилищем в одной транзакции.
func (s *Service) CheckDeadlines(c context.Context, now time.Time) error {
	return s.repo.CheckDeadlines(c, now)
}
