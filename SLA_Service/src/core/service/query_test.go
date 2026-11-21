package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"sla/models"
)

type queryStore struct {
	store
	ctx  context.Context
	args []any
	err  error
}

func (r *queryStore) record(c context.Context, args ...any) { r.ctx = c; r.args = args }
func (r *queryStore) GetRule(c context.Context, id uuid.UUID) (*models.Rule, error) {
	r.record(c, id)
	return &models.Rule{ID: id}, r.err
}
func (r *queryStore) DeleteRule(c context.Context, id uuid.UUID) (*models.Rule, error) {
	r.record(c, id)
	return &models.Rule{ID: id}, r.err
}
func (r *queryStore) ListRules(c context.Context, f models.RuleFilter) ([]*models.Rule, int64, error) {
	r.record(c, f)
	return []*models.Rule{{Name: "rule"}}, 7, r.err
}
func (r *queryStore) GetTicketSLA(c context.Context, id uuid.UUID) (*models.TicketSLA, error) {
	r.record(c, id)
	return &models.TicketSLA{TicketID: id}, r.err
}
func (r *queryStore) ListSLAs(c context.Context, f models.SLAFilter) ([]*models.TicketSLA, int64, error) {
	r.record(c, f)
	return []*models.TicketSLA{{Status: models.StatusActive}}, 7, r.err
}
func (r *queryStore) ListHistory(c context.Context, id uuid.UUID, l, o int32) ([]*models.History, int64, error) {
	r.record(c, id, l, o)
	return []*models.History{{TicketID: id}}, 7, r.err
}
func (r *queryStore) CheckDeadlines(c context.Context, now time.Time) error {
	r.record(c, now)
	return r.err
}

func TestSLAQueryContracts(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rf := models.RuleFilter{DepartmentID: &id, Limit: 7, Offset: 3}
	sf := models.SLAFilter{DepartmentID: &id, Limit: 7, Offset: 3}
	for _, wantErr := range []error{nil, context.DeadlineExceeded} {
		r := &queryStore{err: wantErr}
		s := New(r)
		for _, tt := range []struct {
			name string
			args []any
			call func() (bool, error)
		}{
			{"get rule", []any{id}, func() (bool, error) { v, e := s.GetRule(ctx, id); return v != nil && v.ID == id, e }},
			{"delete rule", []any{id}, func() (bool, error) { v, e := s.DeleteRule(ctx, id); return v != nil && v.ID == id, e }},
			{"list rules", []any{rf}, func() (bool, error) {
				v, n, e := s.ListRules(ctx, rf)
				return len(v) == 1 && v[0].Name == "rule" && n == 7, e
			}},
			{"get ticket SLA", []any{id}, func() (bool, error) { v, e := s.GetTicketSLA(ctx, id); return v != nil && v.TicketID == id, e }},
			{"list SLAs", []any{sf}, func() (bool, error) {
				v, n, e := s.ListSLAs(ctx, sf)
				return len(v) == 1 && v[0].Status == models.StatusActive && n == 7, e
			}},
			{"list history", []any{id, int32(7), int32(3)}, func() (bool, error) {
				v, n, e := s.ListHistory(ctx, id, 7, 3)
				return len(v) == 1 && v[0].TicketID == id && n == 7, e
			}},
			{"check deadlines", []any{now}, func() (bool, error) { return true, s.CheckDeadlines(ctx, now) }},
		} {
			ok, err := tt.call()
			if !ok || !errors.Is(err, wantErr) || r.ctx != ctx || !reflect.DeepEqual(r.args, tt.args) {
				t.Errorf("%s = result valid %v, err %v, args %v; want valid, %v, %v and original context", tt.name, ok, err, r.args, wantErr, tt.args)
			}
		}
	}
}
