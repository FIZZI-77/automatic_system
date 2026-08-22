package service

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"report/models"
	"testing"
	"time"
)

type repoMock struct {
	item      *models.Report
	claimed   bool
	completed bool
	failed    bool
}

func (r *repoMock) Create(context.Context, models.CreateInput) (*models.Report, error) {
	return r.item, nil
}
func (r *repoMock) Get(context.Context, uuid.UUID) (*models.Report, error) { return r.item, nil }
func (r *repoMock) List(context.Context, models.ListFilter) ([]*models.Report, int64, error) {
	return []*models.Report{r.item}, 1, nil
}
func (r *repoMock) Cancel(context.Context, uuid.UUID) (*models.Report, error) { return r.item, nil }
func (r *repoMock) Retry(context.Context, uuid.UUID) (*models.Report, error)  { return r.item, nil }
func (r *repoMock) Claim(context.Context) (*models.Report, error) {
	if !r.claimed {
		r.claimed = true
		return r.item, nil
	}
	return nil, errors.New("empty")
}
func (r *repoMock) Complete(context.Context, uuid.UUID, uuid.UUID) error {
	r.completed = true
	return nil
}
func (r *repoMock) Fail(context.Context, uuid.UUID, string) error { r.failed = true; return nil }

type sourceMock struct{}

func (sourceMock) Build(context.Context, models.Type, models.Filter, []string) ([][]string, error) {
	return [][]string{{"a"}, {"1"}}, nil
}

type genMock struct{}

func (genMock) Generate(models.Format, string, [][]string) (models.Artifact, error) {
	return models.Artifact{Name: "r.csv", ContentType: "text/csv", Data: []byte("a\n1")}, nil
}

type filesMock struct{}

func (filesMock) Upload(context.Context, uuid.UUID, uuid.UUID, []string, models.Artifact) (uuid.UUID, error) {
	return uuid.New(), nil
}
func (filesMock) Download(context.Context, uuid.UUID, uuid.UUID, []string) (string, time.Time, error) {
	return "url", time.Now(), nil
}
func TestProcessNextCompletesReport(t *testing.T) {
	r := &repoMock{item: &models.Report{ID: uuid.New(), RequestedBy: uuid.New(), Name: "Report", Type: models.TypeTicketOverview, Format: models.FormatCSV, Status: models.StatusProcessing}}
	s := NewService(r, sourceMock{}, filesMock{}, genMock{}, nil)
	ok, e := s.ProcessNext(context.Background())
	if e != nil || !ok || !r.completed || r.failed {
		t.Fatalf("ok=%v err=%v completed=%v failed=%v", ok, e, r.completed, r.failed)
	}
}
func TestOwnerAccess(t *testing.T) {
	owner := uuid.New()
	r := &repoMock{item: &models.Report{ID: uuid.New(), RequestedBy: owner}}
	s := NewService(r, sourceMock{}, filesMock{}, genMock{}, nil)
	if _, e := s.Get(context.Background(), r.item.ID, uuid.New(), false); !errors.Is(e, models.ErrForbidden) {
		t.Fatalf("expected forbidden, got %v", e)
	}
	if _, e := s.Get(context.Background(), r.item.ID, owner, false); e != nil {
		t.Fatal(e)
	}
}
