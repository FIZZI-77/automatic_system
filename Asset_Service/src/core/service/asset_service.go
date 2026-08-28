package service

import (
	"asset/models"
	"asset/src/core/repository"
	"context"
	"errors"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"math"
	"time"
)

type AssetServiceStruct struct {
	repo repository.AssetRepository
	log  *zap.Logger
}

func (s *AssetServiceStruct) Create(c context.Context, v models.CreateInput, p bool) (*models.Asset, error) {
	if !p {
		return nil, models.ErrForbidden
	}
	if v.DepartmentID == uuid.Nil || v.Name == "" || v.Type == "" || v.Geometry == "" {
		return nil, errors.New("required asset fields missing")
	}
	if v.Criticality < 0 || v.Criticality > 1 {
		return nil, errors.New("criticality must be between 0 and 1")
	}
	x, e := s.repo.Create(c, v)
	if e == nil {
		s.logger().Info("asset created", zap.String("asset_id", x.ID.String()), zap.String("type", x.Type))
	}
	return x, e
}
func (s *AssetServiceStruct) Get(c context.Context, id uuid.UUID) (*models.Asset, error) {
	return s.repo.Get(c, id)
}
func (s *AssetServiceStruct) Update(c context.Context, v models.UpdateInput, p bool) (*models.Asset, error) {
	if !p {
		return nil, models.ErrForbidden
	}
	if v.Criticality != nil && (*v.Criticality < 0 || *v.Criticality > 1) {
		return nil, errors.New("criticality must be between 0 and 1")
	}
	x, e := s.repo.Update(c, v)
	if e == nil {
		s.logger().Info("asset updated", zap.String("asset_id", x.ID.String()))
	}
	return x, e
}
func (s *AssetServiceStruct) List(c context.Context, f models.Filter) ([]*models.Asset, int64, error) {
	if f.Limit <= 0 {
		f.Limit = 20
	}
	if f.Limit > 100 {
		f.Limit = 100
	}
	return s.repo.List(c, f)
}
func (s *AssetServiceStruct) ChangeStatus(c context.Context, id uuid.UUID, st models.Status, a uuid.UUID, reason string, p bool) (*models.Asset, error) {
	if !p {
		return nil, models.ErrForbidden
	}
	return s.repo.ChangeStatus(c, id, st, a, reason)
}
func (s *AssetServiceStruct) Nearby(c context.Context, lat, lon, r float64, t *string, l int32) ([]*models.Asset, error) {
	if lat < -90 || lat > 90 || lon < -180 || lon > 180 || r <= 0 {
		return nil, errors.New("invalid geo query")
	}
	if l <= 0 || l > 100 {
		l = 20
	}
	return s.repo.Nearby(c, lat, lon, r, t, l)
}
func (s *AssetServiceStruct) Incident(c context.Context, v models.Incident, p bool) (*models.Incident, *models.Prediction, error) {
	if !p {
		return nil, nil, models.ErrForbidden
	}
	x, e := s.repo.RecordIncident(c, v)
	if e != nil {
		return nil, nil, e
	}
	pr, e := s.calculate(c, v.AssetID, time.Now().UTC())
	return x, pr, e
}
func (s *AssetServiceStruct) Repair(c context.Context, v models.Repair, p bool) (*models.Repair, *models.Prediction, error) {
	if !p {
		return nil, nil, models.ErrForbidden
	}
	x, e := s.repo.CompleteRepair(c, v)
	if e != nil {
		return nil, nil, e
	}
	pr, e := s.calculate(c, v.AssetID, time.Now().UTC())
	return x, pr, e
}
func (s *AssetServiceStruct) Inspection(c context.Context, v models.Inspection, p bool) (*models.Inspection, *models.Prediction, error) {
	if !p {
		return nil, nil, models.ErrForbidden
	}
	if v.ConditionScore < 0 || v.ConditionScore > 1 {
		return nil, nil, errors.New("condition score must be between 0 and 1")
	}
	x, e := s.repo.RecordInspection(c, v)
	if e != nil {
		return nil, nil, e
	}
	pr, e := s.calculate(c, v.AssetID, time.Now().UTC())
	return x, pr, e
}
func (s *AssetServiceStruct) CreatePlan(c context.Context, v models.Plan, p bool) (*models.Plan, error) {
	if !p {
		return nil, models.ErrForbidden
	}
	if v.IntervalDays <= 0 {
		return nil, errors.New("interval must be positive")
	}
	return s.repo.CreatePlan(c, v)
}
func (s *AssetServiceStruct) Due(c context.Context, d *uuid.UUID, t time.Time, l, o int32) ([]*models.Plan, int64, error) {
	if l <= 0 {
		l = 20
	}
	return s.repo.DuePlans(c, d, t, l, o)
}
func (s *AssetServiceStruct) Prediction(c context.Context, id uuid.UUID) (*models.Prediction, error) {
	p, e := s.repo.GetPrediction(c, id)
	if repository.IsNotFound(e) {
		return s.calculate(c, id, time.Now().UTC())
	}
	return p, e
}
func (s *AssetServiceStruct) Recalculate(c context.Context, d *uuid.UUID, p bool) (int64, error) {
	if !p {
		return 0, models.ErrForbidden
	}
	ids, e := s.repo.ListIDs(c, d)
	if e != nil {
		return 0, e
	}
	var n int64
	for _, id := range ids {
		if _, e = s.calculate(c, id, time.Now().UTC()); e != nil {
			return n, e
		}
		n++
	}
	return n, nil
}
func (s *AssetServiceStruct) calculate(c context.Context, id uuid.UUID, now time.Time) (*models.Prediction, error) {
	f, e := s.repo.RiskFacts(c, id, now)
	if e != nil {
		return nil, e
	}
	score := f.Criticality * 20
	factors := []string{}
	if f.InstallationYear != nil && f.ServiceLifeYears != nil && *f.ServiceLifeYears > 0 {
		age := now.Year() - int(*f.InstallationYear)
		ratio := float64(age) / float64(*f.ServiceLifeYears)
		score += math.Min(25, ratio*25)
		if ratio >= .8 {
			factors = append(factors, "service life is nearly exhausted")
		}
	}
	score += math.Min(25, float64(f.Incidents90)*7+float64(f.Repeat90)*5)
	if f.Repeat90 > 0 {
		factors = append(factors, "repeated failures within 90 days")
	}
	score += math.Min(15, float64(f.DaysInspectionOverdue)/10)
	if f.DaysInspectionOverdue > 0 {
		factors = append(factors, "inspection is overdue")
	}
	if f.LastCondition != nil {
		score += (1 - *f.LastCondition) * 15
		if *f.LastCondition < .5 {
			factors = append(factors, "poor latest inspection condition")
		}
	}
	score = math.Min(100, math.Round(score*10)/10)
	level := models.RiskLow
	action := "normal scheduled maintenance"
	switch {
	case score >= 75:
		level = models.RiskCritical
		action = "immediate inspection and replacement planning"
	case score >= 60:
		level = models.RiskHigh
		action = "priority inspection and preventive repair"
	case score >= 35:
		level = models.RiskMedium
		action = "shorten inspection interval"
	}
	p := models.Prediction{
		AssetID:      id,
		Score:        score,
		Probability:  math.Round((1-math.Exp(-score/55))*1000) / 10,
		Level:        level,
		Factors:      factors,
		Action:       action,
		CalculatedAt: now,
	}
	e = s.repo.SavePrediction(c, p)
	if e == nil {
		s.logger().Info("asset risk calculated", zap.String("asset_id", id.String()), zap.Float64("score", score), zap.String("level", string(level)))
	}
	return &p, e
}
func (s *AssetServiceStruct) logger() *zap.Logger {
	if s.log == nil {
		return zap.NewNop()
	}
	return s.log
}
