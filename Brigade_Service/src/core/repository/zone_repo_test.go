package repository

import (
	"brigade/models"
	"context"
	"testing"

	"github.com/google/uuid"
)

const testZoneGeoJSON = `{
	"type": "Polygon",
	"coordinates": [[[37.0,55.0],[38.0,55.0],[38.0,56.0],[37.0,56.0],[37.0,55.0]]]
}`

func TestZoneRepository_CreateListUpdateDeleteAndCovers(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepo(db)
	ctx := context.Background()
	departmentID := uuid.New()
	brigade := createTestBrigade(t, repo, departmentID)

	created, err := repo.CreateBrigadeZone(ctx, &models.CreateBrigadeZoneInput{
		BrigadeID:    brigade.ID,
		DepartmentID: departmentID,
		Name:         "North",
		GeoJSON:      testZoneGeoJSON,
		Priority:     10,
	})
	if err != nil {
		t.Fatalf("create zone failed: %v", err)
	}
	if !created.Zone.Active {
		t.Fatal("expected zone active")
	}

	found, err := repo.GetBrigadeZoneByID(ctx, created.Zone.ID)
	if err != nil {
		t.Fatalf("get zone failed: %v", err)
	}
	if found.ID != created.Zone.ID {
		t.Fatalf("expected zone id %s, got %s", created.Zone.ID, found.ID)
	}

	covers, err := repo.CheckBrigadeCoversPoint(ctx, &models.CheckBrigadeCoversPointInput{
		BrigadeID: brigade.ID,
		Longitude: 37.5,
		Latitude:  55.5,
	})
	if err != nil {
		t.Fatalf("check covers failed: %v", err)
	}
	if !covers.Covers || len(covers.MatchedZones) != 1 {
		t.Fatalf("expected matched zone, got %#v", covers)
	}

	name := "Updated North"
	updated, err := repo.UpdateBrigadeZone(ctx, &models.UpdateBrigadeZoneInput{
		ID:   created.Zone.ID,
		Name: &name,
	})
	if err != nil {
		t.Fatalf("update zone failed: %v", err)
	}
	if updated.Zone.Name != name {
		t.Fatalf("expected name %s, got %s", name, updated.Zone.Name)
	}

	deleted, err := repo.DeleteBrigadeZone(ctx, &models.DeleteBrigadeZoneInput{ID: created.Zone.ID})
	if err != nil {
		t.Fatalf("delete zone failed: %v", err)
	}
	if deleted.Zone.Active {
		t.Fatal("expected deleted zone inactive")
	}
}

func TestZoneRepository_FindBrigadesByPoint(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepo(db)
	ctx := context.Background()
	departmentID := uuid.New()
	brigade := createTestBrigade(t, repo, departmentID)

	_, err := repo.CreateBrigadeZone(ctx, &models.CreateBrigadeZoneInput{
		BrigadeID:    brigade.ID,
		DepartmentID: departmentID,
		Name:         "North",
		GeoJSON:      testZoneGeoJSON,
		Priority:     10,
	})
	if err != nil {
		t.Fatalf("create zone failed: %v", err)
	}

	result, err := repo.FindBrigadesByPoint(ctx, &models.FindBrigadesByPointInput{
		DepartmentID: departmentID,
		Longitude:    37.5,
		Latitude:     55.5,
		Limit:        10,
		Offset:       0,
	})
	if err != nil {
		t.Fatalf("find brigades by point failed: %v", err)
	}
	if result.Total != 1 || len(result.Brigades) != 1 {
		t.Fatalf("expected one brigade, got total=%d len=%d", result.Total, len(result.Brigades))
	}
}
