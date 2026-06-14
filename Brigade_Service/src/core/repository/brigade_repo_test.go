package repository

import (
	"brigade/models"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestBrigadeRepository_CreateGetListUpdateStatus(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepo(db)
	ctx := context.Background()
	departmentID := uuid.New()

	created := createTestBrigade(t, repo, departmentID)
	if created.Status != models.BrigadeStatusInactive {
		t.Fatalf("expected inactive status, got %s", created.Status)
	}

	found, err := repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{ID: created.ID})
	if err != nil {
		t.Fatalf("get brigade failed: %v", err)
	}
	if found.Brigade.ID != created.ID {
		t.Fatalf("expected brigade id %s, got %s", created.ID, found.Brigade.ID)
	}

	list, err := repo.ListBrigades(ctx, &models.ListBrigadesInput{
		DepartmentID: &departmentID,
		Limit:        10,
		Offset:       0,
	})
	if err != nil {
		t.Fatalf("list brigades failed: %v", err)
	}
	if list.Total != 1 || len(list.Brigades) != 1 {
		t.Fatalf("expected one brigade, got total=%d len=%d", list.Total, len(list.Brigades))
	}

	name := "Updated brigade"
	updated, err := repo.UpdateBrigade(ctx, &models.UpdateBrigadeInput{ID: created.ID, Name: &name})
	if err != nil {
		t.Fatalf("update brigade failed: %v", err)
	}
	if updated.Brigade.Name != name {
		t.Fatalf("expected updated name %s, got %s", name, updated.Brigade.Name)
	}

	statusResult, err := repo.SetBrigadeStatus(ctx, &models.SetBrigadeStatusInput{
		BrigadeID: created.ID,
		Status:    models.BrigadeStatusActive,
		Reason:    "ready",
	})
	if err != nil {
		t.Fatalf("set brigade status failed: %v", err)
	}
	if statusResult.Brigade.Status != models.BrigadeStatusActive {
		t.Fatalf("expected active status, got %s", statusResult.Brigade.Status)
	}

	history, err := repo.GetBrigadeStatusHistory(ctx, &models.GetBrigadeStatusHistoryInput{BrigadeID: created.ID, Limit: 10})
	if err != nil {
		t.Fatalf("get status history failed: %v", err)
	}
	if history.Total != 1 || len(history.History) != 1 {
		t.Fatalf("expected one history item, got total=%d len=%d", history.Total, len(history.History))
	}
}

func TestBrigadeRepository_DuplicateName(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepo(db)
	ctx := context.Background()
	departmentID := uuid.New()

	_, err := repo.CreateBrigade(ctx, &models.CreateBrigadeInput{DepartmentID: departmentID, Name: "North"})
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	_, err = repo.CreateBrigade(ctx, &models.CreateBrigadeInput{DepartmentID: departmentID, Name: "North"})
	if !errors.Is(err, models.ErrAlreadyExists) {
		t.Fatalf("expected already exists, got %v", err)
	}
}

func TestBrigadeRepository_Readiness(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepo(db)
	ctx := context.Background()
	brigade := createTestBrigade(t, repo, uuid.New())

	reasons, err := repo.CheckBrigadeReadiness(ctx, brigade.ID, false, nil)
	if err != nil {
		t.Fatalf("check readiness failed: %v", err)
	}
	if len(reasons) == 0 {
		t.Fatal("expected readiness reasons without members")
	}

	createTestMember(t, repo, brigade.ID)
	reasons, err = repo.CheckBrigadeReadiness(ctx, brigade.ID, false, []models.BrigadeMemberRole{models.BrigadeMemberRoleLead})
	if err != nil {
		t.Fatalf("check readiness with member failed: %v", err)
	}
	if len(reasons) != 0 {
		t.Fatalf("expected no readiness reasons, got %#v", reasons)
	}
}
