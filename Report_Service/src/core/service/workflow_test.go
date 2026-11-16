package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"report/models"
	"report/src/core/repository"
)

type pipelineRepo struct {
	repository.ReportRepository
	item                           *models.Report
	claimErr, completeErr, failErr error
	failed, completed              bool
}

func (r *pipelineRepo) Claim(context.Context) (*models.Report, error) { return r.item, r.claimErr }
func (r *pipelineRepo) Complete(_ context.Context, id, file uuid.UUID, attempt int32) error {
	if id != r.item.ID || file == uuid.Nil || attempt != r.item.Attempts {
		return errors.New("incorrect completion arguments")
	}
	r.completed = true
	return r.completeErr
}
func (r *pipelineRepo) Fail(_ context.Context, id uuid.UUID, attempt int32, message string) error {
	if id != r.item.ID || attempt != r.item.Attempts || message == "" {
		return errors.New("incorrect failure arguments")
	}
	r.failed = true
	return r.failErr
}

type pipelineSource struct {
	err    error
	called bool
}

func (s *pipelineSource) Build(context.Context, models.Type, models.Filter, []string) ([][]string, error) {
	s.called = true
	return [][]string{{"header"}, {"value"}}, s.err
}

type pipelineGenerator struct {
	err    error
	called bool
}

func (g *pipelineGenerator) Generate(models.Format, string, [][]string) (models.Artifact, error) {
	g.called = true
	return models.Artifact{Data: []byte("file")}, g.err
}

type pipelineFiles struct {
	err       error
	uploaded  bool
	id, actor uuid.UUID
	roles     []string
}

func (f *pipelineFiles) Upload(_ context.Context, id, actor uuid.UUID, roles []string, a models.Artifact) (uuid.UUID, error) {
	f.uploaded = true
	f.id = id
	f.actor = actor
	f.roles = roles
	if len(a.Data) == 0 {
		return uuid.Nil, errors.New("empty artifact")
	}
	return uuid.New(), f.err
}
func (f *pipelineFiles) Download(_ context.Context, id, actor uuid.UUID, roles []string) (string, time.Time, error) {
	f.id = id
	f.actor = actor
	f.roles = roles
	return "https://files/report", time.Unix(123, 0), f.err
}

func TestProcessNextFailures(t *testing.T) {
	t.Parallel()
	failure := errors.New("dependency failed")
	for _, tt := range []struct {
		name, stage string
		failErr     error
	}{
		{name: "source", stage: "source"}, {name: "generator", stage: "generator"}, {name: "upload", stage: "upload"}, {name: "complete", stage: "complete"}, {name: "failure recording also fails", stage: "source", failErr: context.Canceled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &pipelineRepo{item: &models.Report{ID: uuid.New(), RequestedBy: uuid.New(), Attempts: 3, ActorRoles: []string{"admin"}}, failErr: tt.failErr}
			source := &pipelineSource{}
			gen := &pipelineGenerator{}
			files := &pipelineFiles{}
			switch tt.stage {
			case "source":
				source.err = failure
			case "generator":
				gen.err = failure
			case "upload":
				files.err = failure
			case "complete":
				r.completeErr = failure
			}
			claimed, err := NewService(r, source, files, gen, nil).ProcessNext(context.Background())
			if !claimed || !errors.Is(err, failure) || !r.failed || !source.called || gen.called != (tt.stage != "source") || files.uploaded != (tt.stage == "upload" || tt.stage == "complete") || r.completed != (tt.stage == "complete") {
				t.Fatalf("ProcessNext(%s) = %v, %v, failed=%v source=%v generated=%v uploaded=%v completed=%v", tt.stage, claimed, err, r.failed, source.called, gen.called, files.uploaded, r.completed)
			}
			if files.uploaded && (files.id != r.item.ID || files.actor != r.item.RequestedBy || !reflect.DeepEqual(files.roles, r.item.ActorRoles)) {
				t.Fatalf("Upload identity = %+v, want report owner and roles", files)
			}
		})
	}
	for _, wantErr := range []error{pgx.ErrNoRows, failure} {
		r := &pipelineRepo{claimErr: wantErr}
		claimed, err := NewService(r, nil, nil, nil, nil).ProcessNext(context.Background())
		if errors.Is(wantErr, pgx.ErrNoRows) {
			wantErr = nil
		}
		if claimed || !errors.Is(err, wantErr) || r.failed {
			t.Fatalf("ProcessNext(claim error) = %v, %v; want false, %v", claimed, err, wantErr)
		}
	}
}

type accessRepo struct {
	repository.ReportRepository
	item   *models.Report
	err    error
	filter models.ListFilter
	calls  int
}

func (r *accessRepo) Get(context.Context, uuid.UUID) (*models.Report, error) { return r.item, r.err }
func (r *accessRepo) Create(_ context.Context, v models.CreateInput) (*models.Report, error) {
	r.calls++
	return r.item, r.err
}
func (r *accessRepo) List(_ context.Context, f models.ListFilter) ([]*models.Report, int64, error) {
	r.filter = f
	return []*models.Report{r.item}, 7, r.err
}
func (r *accessRepo) Cancel(context.Context, uuid.UUID) (*models.Report, error) {
	r.calls++
	return r.item, pgx.ErrNoRows
}
func (r *accessRepo) Retry(context.Context, uuid.UUID) (*models.Report, error) {
	r.calls++
	return r.item, pgx.ErrNoRows
}

func TestReportListScope(t *testing.T) {
	t.Parallel()
	actor := uuid.New()
	status := models.StatusFailed
	for _, tt := range []struct {
		name             string
		privileged       bool
		limit, wantLimit int32
	}{
		{"default", false, 0, 20}, {"cap", false, 500, 100}, {"admin sees all", true, 15, 15},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &accessRepo{}
			_, total, err := NewService(r, nil, nil, nil, nil).List(context.Background(), actor, tt.privileged, &status, tt.limit, 4)
			if err != nil || total != 7 || r.filter.Limit != tt.wantLimit || r.filter.Offset != 4 || r.filter.Status != &status || (r.filter.RequestedBy == nil) != tt.privileged {
				t.Fatalf("List = %v, %v, filter=%+v; want scoped filter limit=%d", total, err, r.filter, tt.wantLimit)
			}
			if !tt.privileged && *r.filter.RequestedBy != actor {
				t.Fatal("List exposed another owner's reports")
			}
		})
	}
}
func TestReportTransitionsAndDownload(t *testing.T) {
	t.Parallel()
	owner := uuid.New()
	file := uuid.New()
	roles := []string{"user"}
	r := &accessRepo{item: &models.Report{ID: uuid.New(), RequestedBy: owner, Status: models.StatusPending}}
	files := &pipelineFiles{}
	s := NewService(r, nil, files, nil, nil)
	for _, call := range []func(context.Context, uuid.UUID, uuid.UUID, bool) (*models.Report, error){s.Cancel, s.Retry} {
		if _, err := call(context.Background(), r.item.ID, uuid.New(), false); !errors.Is(err, models.ErrForbidden) || r.calls != 0 {
			t.Fatalf("transition by stranger = %v, writes=%d; want forbidden without write", err, r.calls)
		}
		if _, err := call(context.Background(), r.item.ID, owner, false); !errors.Is(err, models.ErrInvalidState) {
			t.Fatalf("transition with stale state = %v; want invalid state", err)
		}
		r.calls = 0
	}
	if _, err := s.Download(context.Background(), r.item.ID, owner, roles, false); !errors.Is(err, models.ErrInvalidState) {
		t.Fatalf("Download(pending) = %v; want invalid state", err)
	}
	r.item.Status = models.StatusCompleted
	if _, err := s.Download(context.Background(), r.item.ID, owner, roles, false); !errors.Is(err, models.ErrInvalidState) {
		t.Fatalf("Download(no file) = %v; want invalid state", err)
	}
	r.item.FileID = &file
	got, err := s.Download(context.Background(), r.item.ID, owner, roles, false)
	if err != nil || got.URL != "https://files/report" || !got.ExpiresAt.Equal(time.Unix(123, 0)) || files.id != file || files.actor != owner || !reflect.DeepEqual(files.roles, roles) {
		t.Fatalf("Download(completed) = %+v, %v, identity=%+v", got, err, files)
	}
	if _, err := s.Download(context.Background(), r.item.ID, uuid.New(), roles, false); !errors.Is(err, models.ErrForbidden) {
		t.Fatalf("Download(stranger) = %v; want forbidden", err)
	}
	if _, err := s.Get(context.Background(), r.item.ID, uuid.New(), true); err != nil {
		t.Fatalf("Get(admin) = %v", err)
	}
	r.err = context.Canceled
	if _, err := s.Get(context.Background(), r.item.ID, owner, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get(storage error) = %v", err)
	}
}
func TestReportCreateValidation(t *testing.T) {
	t.Parallel()
	r := &accessRepo{item: &models.Report{ID: uuid.New()}}
	s := NewService(r, nil, nil, nil, nil)
	if _, err := s.Create(context.Background(), models.CreateInput{}); err == nil || r.calls != 0 {
		t.Fatalf("Create(invalid) = %v, writes=%d", err, r.calls)
	}
	v := models.CreateInput{RequestedBy: uuid.New(), Name: "Report", Type: models.TypeTicketOverview, Format: models.FormatCSV}
	got, err := s.Create(context.Background(), v)
	if err != nil || got != r.item || r.calls != 1 {
		t.Fatalf("Create(valid) = %v, %v, writes=%d", got, err, r.calls)
	}
}
