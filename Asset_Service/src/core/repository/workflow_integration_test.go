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

func TestAssetIncidentHistoryChronologyAndReplay(t *testing.T) {
	repo := NewAssetRepoStruct(peripheralPool(t))
	ctx := t.Context()
	asset, err := repo.Create(ctx, models.CreateInput{Asset: models.Asset{
		DepartmentID: uuid.New(), Name: "lamp", Type: "LIGHT",
		Geometry: `{"type":"Point","coordinates":[37,55]}`, Criticality: .5, InspectionIntervalDays: 30,
	}, ActorID: uuid.New()})
	if err != nil {
		t.Fatalf("Create = %v", err)
	}

	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	ticketID := uuid.New()
	projected := models.Incident{
		AssetID: asset.ID, TicketID: &ticketID, FailureType: "leak",
		OccurredAt: now, Source: "TICKET", Priority: "HIGH",
	}
	for range 2 {
		if err := repo.RecordTicketIncident(ctx, projected); err != nil {
			t.Fatalf("RecordTicketIncident = %v", err)
		}
	}
	firstPage, total, err := repo.ListIncidents(ctx, asset.ID, 1, 0)
	if err != nil || total != 1 || len(firstPage) != 1 {
		t.Fatalf("ListIncidents(after replay) = %+v, %d, %v; want one record", firstPage, total, err)
	}
	if firstPage[0].Repeated || firstPage[0].TicketID == nil || *firstPage[0].TicketID != ticketID {
		t.Fatalf("projected incident = %+v; want first incident for ticket %s", firstPage[0], ticketID)
	}

	older, err := repo.RecordIncident(ctx, models.Incident{
		AssetID: asset.ID, FailureType: "leak", OccurredAt: now.AddDate(0, 0, -1), Source: "WEB", Priority: "HIGH",
	})
	if err != nil || older.Repeated {
		t.Fatalf("RecordIncident(older) = %+v, %v; want no prior occurrence", older, err)
	}
	all, total, err := repo.ListIncidents(ctx, asset.ID, 20, 0)
	if err != nil || total != 2 || len(all) != 2 || !all[0].Repeated || all[1].Repeated || all[1].ID != older.ID {
		t.Fatalf("ListIncidents(backdated) = %+v, %d, %v; want the later incident marked repeated", all, total, err)
	}
}
