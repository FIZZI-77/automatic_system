package service

import (
	"context"
	"errors"
	"report/models"
	"report/src/core/repository"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

type ReportServiceStruct struct {
	repo      repository.ReportRepository
	source    AnalyticsSource
	files     FileStorage
	generator Generator
	logger    *zap.Logger
}

func (s *ReportServiceStruct) Create(c context.Context, v models.CreateInput) (*models.Report, error) {
	if e := v.Validate(); e != nil {
		return nil, e
	}
	x, e := s.repo.Create(c, v)
	if e == nil {
		s.log().Info("report queued", zap.String("report_id", x.ID.String()), zap.String("type", string(x.Type)), zap.String("format", string(x.Format)))
	}
	return x, e
}
func (s *ReportServiceStruct) Get(c context.Context, id, actor uuid.UUID, privileged bool) (*models.Report, error) {
	x, e := s.repo.Get(c, id)
	if e == nil && x.RequestedBy != actor && !privileged {
		return nil, models.ErrForbidden
	}
	return x, e
}
func (s *ReportServiceStruct) List(c context.Context, actor uuid.UUID, privileged bool, status *models.Status, limit, offset int32) ([]*models.Report, int64, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	f := models.ListFilter{Status: status, Limit: limit, Offset: offset}
	if !privileged {
		f.RequestedBy = &actor
	}
	return s.repo.List(c, f)
}
func (s *ReportServiceStruct) Cancel(c context.Context, id, actor uuid.UUID, p bool) (*models.Report, error) {
	if _, e := s.Get(c, id, actor, p); e != nil {
		return nil, e
	}
	x, e := s.repo.Cancel(c, id)
	if repository.IsNotFound(e) {
		return nil, models.ErrInvalidState
	}
	return x, e
}
func (s *ReportServiceStruct) Retry(c context.Context, id, actor uuid.UUID, p bool) (*models.Report, error) {
	if _, e := s.Get(c, id, actor, p); e != nil {
		return nil, e
	}
	x, e := s.repo.Retry(c, id)
	if repository.IsNotFound(e) {
		return nil, models.ErrInvalidState
	}
	return x, e
}
func (s *ReportServiceStruct) Download(c context.Context, id, actor uuid.UUID, roles []string, p bool) (models.Download, error) {
	x, e := s.Get(c, id, actor, p)
	if e != nil {
		return models.Download{}, e
	}
	if x.Status != models.StatusCompleted || x.FileID == nil {
		return models.Download{}, models.ErrInvalidState
	}
	url, expires, e := s.files.Download(c, *x.FileID, actor, roles)
	return models.Download{Report: x, URL: url, ExpiresAt: expires}, e
}
func (s *ReportServiceStruct) ProcessNext(c context.Context) (bool, error) {
	x, e := s.repo.Claim(c)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	start := time.Now()
	rows, e := s.source.Build(c, x.Type, x.Filter, x.ActorRoles)
	if e == nil {
		var artifact models.Artifact
		artifact, e = s.generator.Generate(x.Format, x.Name, rows)
		if e == nil {
			var file uuid.UUID
			file, e = s.files.Upload(c, x.ID, x.RequestedBy, x.ActorRoles, artifact)
			if e == nil {
				e = s.repo.Complete(c, x.ID, file)
			}
		}
	}
	if e != nil {
		if failErr := s.repo.Fail(c, x.ID, e.Error()); failErr != nil {
			s.log().Error("report failure state update failed", zap.String("report_id", x.ID.String()), zap.Error(failErr))
		}
		s.log().Error("report generation failed", zap.String("report_id", x.ID.String()), zap.Error(e))
		return true, e
	}
	s.log().Info("report generated", zap.String("report_id", x.ID.String()), zap.Duration("duration", time.Since(start)))
	return true, nil
}
func (s *ReportServiceStruct) log() *zap.Logger {
	if s.logger == nil {
		return zap.NewNop()
	}
	return s.logger
}
