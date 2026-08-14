package service

import (
	"context"
	"testing"

	"analytics/models"
	"analytics/src/core/repository"
)

type fakeRepository struct{ stored bool }

func (f *fakeRepository) Store(context.Context, models.Event) error { f.stored = true; return nil }
func (*fakeRepository) Overview(context.Context, models.Filter) (models.Overview, error) {
	return models.Overview{Created: 7}, nil
}
func (*fakeRepository) SLA(context.Context, models.Filter) (models.SLA, error) {
	return models.SLA{ResponseBreaches: 2}, nil
}
func (*fakeRepository) Breakdown(context.Context, models.Filter, string, int32) ([]models.Breakdown, uint64, error) {
	return []models.Breakdown{{Key: "HIGH", Count: 3}}, 3, nil
}
func (*fakeRepository) Daily(context.Context, models.Filter) ([]models.Daily, error) {
	return []models.Daily{{Created: 1}}, nil
}

func TestServiceUsesPorts(t *testing.T) {
	repo := &repository.Repository{EventRepository: new(fakeRepository), OverviewRepository: new(fakeRepository), SLARepository: new(fakeRepository), BreakdownRepository: new(fakeRepository), DailyRepository: new(fakeRepository)}
	svc := NewService(repo, nil)
	if err := svc.Consume(context.Background(), models.Event{}); err != nil || !repo.EventRepository.(*fakeRepository).stored {
		t.Fatal("writer was not used")
	}
	v, err := svc.Overview(context.Background(), models.Filter{})
	if err != nil || v.Created != 7 {
		t.Fatal("reader was not used")
	}
}
