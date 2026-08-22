package service

import (
	"context"
	"testing"

	"audit/models"
	"audit/src/core/repository"
	"github.com/google/uuid"
)

type fakeRepository struct{ stored bool }

func (f *fakeRepository) Store(context.Context, models.Event) error { f.stored = true; return nil }
func (*fakeRepository) Get(context.Context, uuid.UUID) (*models.Entry, error) {
	return &models.Entry{Action: "ticket.created"}, nil
}
func (*fakeRepository) List(context.Context, models.Filter) ([]*models.Entry, int64, error) {
	return []*models.Entry{{Action: "ticket.created"}}, 1, nil
}

func TestServiceUsesPorts(t *testing.T) {
	repo := &repository.Repository{EntryWriterRepository: new(fakeRepository), EntryReaderRepository: new(fakeRepository)}
	svc := NewService(repo)
	if err := svc.Consume(context.Background(), models.Event{}); err != nil || !repo.EntryWriterRepository.(*fakeRepository).stored {
		t.Fatal("writer was not used")
	}
	entry, err := svc.Get(context.Background(), uuid.New())
	if err != nil || entry.Action != "ticket.created" {
		t.Fatal("reader was not used")
	}
}
