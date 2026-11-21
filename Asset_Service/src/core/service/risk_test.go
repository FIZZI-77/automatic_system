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
	r := &riskRepo{facts: repository.RiskFacts{
		InstallationYear:      &y,
		ServiceLifeYears:      &l,
		Criticality:           .9,
		Incidents90:           4,
		Repeat90:              2,
		DaysInspectionOverdue: 60,
		LastCondition:         &condition,
	}}
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

func TestRiskFutureInstallationYearCannotLowerScore(t *testing.T) {
	year, life := int32(2030), int32(20)
	r := &riskRepo{facts: repository.RiskFacts{
		InstallationYear: &year,
		ServiceLifeYears: &life,
		Criticality:      0.5,
	}}
	s := &AssetServiceStruct{repo: r}
	p, err := s.calculate(context.Background(), uuid.New(), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	if err != nil {
		t.Fatal(err)
	}

	if p.Score != 10 {
		t.Fatalf("future installation year changed score: got %v, want 10", p.Score)
	}

}

func TestRiskLevelBoundaries(t *testing.T) {
	t.Parallel()
	condition := 0.0
	for _, tt := range []struct {
		name  string
		facts repository.RiskFacts
		score float64
		level models.RiskLevel
	}{
		{name: "low", score: 0, level: models.RiskLow},
		{name: "medium threshold", facts: repository.RiskFacts{Criticality: 1, LastCondition: &condition}, score: 35, level: models.RiskMedium},
		{name: "high threshold", facts: repository.RiskFacts{Criticality: 1, LastCondition: &condition, Incidents90: 4}, score: 60, level: models.RiskHigh},
		{name: "critical threshold", facts: repository.RiskFacts{Criticality: 1, LastCondition: &condition, Incidents90: 4, DaysInspectionOverdue: 150}, score: 75, level: models.RiskCritical},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &riskRepo{facts: tt.facts}
			s := &AssetServiceStruct{repo: r}
			id := uuid.New()
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			p, err := s.calculate(context.Background(), id, now)
			if err != nil || p.Score != tt.score || p.Level != tt.level || p.AssetID != id || !p.CalculatedAt.Equal(now) || r.saved.Score != tt.score || p.Probability < 0 || p.Probability > 100 || p.Action == "" {
				t.Fatalf("calculate(%+v) = %+v, %v; want score=%v level=%v and persisted timestamp", tt.facts, p, err, tt.score, tt.level)
			}
		})
	}
}
