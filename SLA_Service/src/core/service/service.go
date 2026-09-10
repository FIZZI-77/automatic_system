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

func New(r *repository.Repository) *Service { return &Service{repo: r} }
func (s *Service) CreateRule(c context.Context, v *models.Rule) (*models.Rule, error) {
	if e := v.Validate(); e != nil {
		return nil, e
	}
	return s.repo.CreateRule(c, v)
}
func (s *Service) GetRule(c context.Context, id uuid.UUID) (*models.Rule, error) {
	return s.repo.GetRule(c, id)
}
func (s *Service) UpdateRule(c context.Context, v *models.Rule) (*models.Rule, error) {
	if e := v.Validate(); e != nil {
		return nil, e
	}
	return s.repo.UpdateRule(c, v)
}
func (s *Service) DeleteRule(c context.Context, id uuid.UUID) (*models.Rule, error) {
	return s.repo.DeleteRule(c, id)
}
func (s *Service) ListRules(c context.Context, f models.RuleFilter) ([]*models.Rule, int64, error) {
	return s.repo.ListRules(c, f)
}
func (s *Service) GetTicketSLA(c context.Context, id uuid.UUID) (*models.TicketSLA, error) {
	return s.repo.GetTicketSLA(c, id)
}
func (s *Service) ListSLAs(c context.Context, f models.SLAFilter) ([]*models.TicketSLA, int64, error) {
	return s.repo.ListSLAs(c, f)
}
func (s *Service) ListHistory(c context.Context, id uuid.UUID, l, o int32) ([]*models.History, int64, error) {
	return s.repo.ListHistory(c, id, l, o)
}
func (s *Service) Consume(c context.Context, e models.TicketEvent) error {
	if e.EventID == "" || e.TicketID == uuid.Nil {
		return fmt.Errorf("%w: invalid ticket event", models.ErrInvalidArgument)
	}
	var rule *models.Rule
	if e.EventType == "ticket.created" || e.EventType == "ticket.updated" {
		var err error
		rule, err = s.repo.MatchRule(c, e.DepartmentID, e.CategoryID, e.Priority)
		if err != nil {
			return err
		}
	}
	return s.repo.ApplyEvent(c, e, rule)
}
func (s *Service) CheckDeadlines(c context.Context, now time.Time) error {
	return s.repo.CheckDeadlines(c, now)
}
