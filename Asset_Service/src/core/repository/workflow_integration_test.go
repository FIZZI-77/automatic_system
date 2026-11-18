//go:build integration

package repository

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"asset/models"
)

func TestAssetIncidentRepairAndPredictionOutbox(t *testing.T) {
	pool := peripheralPool(t)
	r := NewAssetRepoStruct(pool)
	ctx := t.Context()
	v, err := r.Create(ctx, models.CreateInput{Asset: models.Asset{DepartmentID: uuid.New(), Name: "pump", Type: "pump", Geometry: `{"type":"Point","coordinates":[37,55]}`, Criticality: .5, InspectionIntervalDays: 30}, ActorID: uuid.New()})
	if err != nil {
		t.Fatalf("Create = %v", err)
	}
	for range 2 {
		if _, err := r.RecordIncident(ctx, models.Incident{AssetID: v.ID, FailureType: "leak", OccurredAt: time.Now().UTC(), Source: "manual", Priority: "HIGH"}); err != nil {
			t.Fatalf("RecordIncident = %v", err)
		}
	}
	got, err := r.Get(ctx, v.ID)
	if err != nil || got.Status != models.StatusDamaged {
		t.Fatalf("Get(damaged) = %+v, %v", got, err)
	}
	facts, err := r.RiskFacts(ctx, v.ID, time.Now().UTC())
	if err != nil || facts.Incidents90 != 2 || facts.Repeat90 != 1 {
		t.Fatalf("RiskFacts = %+v, %v; want 2 incidents and 1 repeat", facts, err)
	}
	if _, err := r.CompleteRepair(ctx, models.Repair{AssetID: v.ID, CompletedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CompleteRepair = %v", err)
	}
	got, err = r.Get(ctx, v.ID)
	if err != nil || got.Status != models.StatusActive || got.LastRepairAt == nil {
		t.Fatalf("Get(repaired) = %+v, %v", got, err)
	}
	prediction := models.Prediction{AssetID: v.ID, Score: 80, Probability: 76.6, Level: models.RiskCritical, Factors: []string{"repeated failures"}, Action: "inspect", CalculatedAt: time.Now().UTC()}
	if err := r.SavePrediction(ctx, prediction); err != nil {
		t.Fatalf("SavePrediction = %v", err)
	}
	p, err := r.GetPrediction(ctx, v.ID)
	if err != nil || p.Score != 80 || p.Level != models.RiskCritical {
		t.Fatalf("GetPrediction = %+v, %v", p, err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE aggregate_id=$1`, v.ID).Scan(&count); err != nil || count < 5 {
		t.Fatalf("asset outbox = %d, %v; want at least 5 events", count, err)
	}
}
