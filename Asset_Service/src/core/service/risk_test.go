package service

import (
	"asset/models"
	"asset/src/core/repository"
	"context"
	"github.com/google/uuid"
	"testing"
	"time"
)

type riskRepo struct {
	repository.AssetRepository
	facts repository.RiskFacts
	saved models.Prediction
}

func (r *riskRepo) RiskFacts(context.Context, uuid.UUID, time.Time) (repository.RiskFacts, error) {
	return r.facts, nil
}
func (r *riskRepo) SavePrediction(_ context.Context, p models.Prediction) error {
	r.saved = p
	return nil
}
func TestRiskRepeatedFailures(t *testing.T) {
	year, life := 2010, 20
	y, l := int32(year), int32(life)
	condition := .3
	r := &riskRepo{facts: repository.RiskFacts{InstallationYear: &y, ServiceLifeYears: &l, Criticality: .9, Incidents90: 4, Repeat90: 2, DaysInspectionOverdue: 60, LastCondition: &condition}}
	s := &AssetServiceStruct{repo: r}
	p, e := s.calculate(context.Background(), uuid.New(), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if e != nil {
		t.Fatal(e)
	}
	if p.Level != models.RiskCritical || p.Score < 75 {
		t.Fatalf("unexpected prediction: %+v", p)
	}
	if len(p.Factors) < 2 {
		t.Fatal("prediction must be explainable")
	}
}
