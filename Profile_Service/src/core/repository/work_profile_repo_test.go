package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"profile/models"
)

func TestWorkProfileRepository_CreateGetListUpdateStatusAndResolve(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()
	userProfile := createTestUserProfile(t, repo)
	departmentID := uuid.New()

	created := createTestWorkProfile(t, repo, userProfile.ID, departmentID)
	if created.WorkProfile.Status != models.WorkProfileStatusActive {
		t.Fatalf("expected ACTIVE status, got %s", created.WorkProfile.Status)
	}

	foundByID, err := repo.GetWorkProfileByID(ctx, &models.GetWorkProfileByIDInput{ID: created.WorkProfile.ID})
	if err != nil {
		t.Fatalf("get work profile by id failed: %v", err)
	}
	if foundByID.Details.UserProfile.ID != userProfile.ID {
		t.Fatalf("expected user profile id %s, got %s", userProfile.ID, foundByID.Details.UserProfile.ID)
	}

	foundByUserID, err := repo.GetWorkProfileByUserID(ctx, &models.GetWorkProfileByUserIDInput{UserID: userProfile.UserID})
	if err != nil {
		t.Fatalf("get work profile by user id failed: %v", err)
	}
	if foundByUserID.Details.WorkProfile.ID != created.WorkProfile.ID {
		t.Fatalf("expected work profile id %s, got %s", created.WorkProfile.ID, foundByUserID.Details.WorkProfile.ID)
	}

	list, err := repo.ListWorkProfiles(ctx, &models.ListWorkProfilesInput{
		DepartmentID: &departmentID,
		Limit:        10,
		Offset:       0,
		SortBy:       models.WorkProfileSortByCreatedAt,
		SortOrder:    models.SortOrderDesc,
	})
	if err != nil {
		t.Fatalf("list work profiles failed: %v", err)
	}
	if list.Total != 1 || len(list.WorkProfiles) != 1 {
		t.Fatalf("expected one work profile, got total=%d len=%d", list.Total, len(list.WorkProfiles))
	}

	employeeNumber := "EMP-001"
	position := "Senior engineer"
	updated, err := repo.UpdateWorkProfile(ctx, &models.UpdateWorkProfileInput{
		ID:             created.WorkProfile.ID,
		EmployeeNumber: &employeeNumber,
		Position:       &position,
	})
	if err != nil {
		t.Fatalf("update work profile failed: %v", err)
	}
	if updated.Details.WorkProfile.EmployeeNumber == nil || *updated.Details.WorkProfile.EmployeeNumber != employeeNumber {
		t.Fatalf("expected employee number %s, got %v", employeeNumber, updated.Details.WorkProfile.EmployeeNumber)
	}

	statusResult, err := repo.SetWorkProfileStatus(ctx, &models.SetWorkProfileStatusInput{
		ID:     created.WorkProfile.ID,
		Status: models.WorkProfileStatusOnShift,
		Reason: "start shift",
	})
	if err != nil {
		t.Fatalf("set work profile status failed: %v", err)
	}
	if statusResult.Details.WorkProfile.Status != models.WorkProfileStatusOnShift {
		t.Fatalf("expected ON_SHIFT, got %s", statusResult.Details.WorkProfile.Status)
	}

	history, err := repo.GetWorkProfileStatusHistory(ctx, &models.GetWorkProfileStatusHistoryInput{
		WorkProfileID: created.WorkProfile.ID,
		Limit:         10,
		Offset:        0,
	})
	if err != nil {
		t.Fatalf("get status history failed: %v", err)
	}
	if history.Total < 2 {
		t.Fatalf("expected at least two history rows, got %d", history.Total)
	}

	resolve, err := repo.ResolveWorkingDepartment(ctx, &models.ResolveWorkingDepartmentInput{UserID: userProfile.UserID})
	if err != nil {
		t.Fatalf("resolve working department failed: %v", err)
	}
	if resolve.DepartmentID != departmentID || !resolve.CanOperate {
		t.Fatalf("unexpected resolve result: %+v", resolve)
	}
}

func TestWorkProfileRepository_CheckProfileCanJoinBrigade(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()
	userProfile := createTestUserProfile(t, repo)
	departmentID := uuid.New()
	otherDepartmentID := uuid.New()
	workProfile := createTestWorkProfile(t, repo, userProfile.ID, departmentID)

	allowed, err := repo.CheckProfileCanJoinBrigade(ctx, &models.CheckProfileCanJoinBrigadeInput{
		WorkProfileID:       &workProfile.WorkProfile.ID,
		BrigadeDepartmentID: departmentID,
	})
	if err != nil {
		t.Fatalf("check can join failed: %v", err)
	}
	if !allowed.Allowed || allowed.Reason != models.CanJoinBrigadeReasonAllowed {
		t.Fatalf("expected allowed, got %+v", allowed)
	}

	denied, err := repo.CheckProfileCanJoinBrigade(ctx, &models.CheckProfileCanJoinBrigadeInput{
		UserID:              &userProfile.UserID,
		BrigadeDepartmentID: otherDepartmentID,
	})
	if err != nil {
		t.Fatalf("check can join wrong department failed: %v", err)
	}
	if denied.Allowed || denied.Reason != models.CanJoinBrigadeReasonDepartmentMismatch {
		t.Fatalf("expected department mismatch, got %+v", denied)
	}
}

func TestWorkProfileRepository_DeactivateWorkProfile(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()
	userProfile := createTestUserProfile(t, repo)
	workProfile := createTestWorkProfile(t, repo, userProfile.ID, uuid.New())

	result, err := repo.DeactivateWorkProfile(ctx, &models.DeactivateWorkProfileInput{
		ID:     workProfile.WorkProfile.ID,
		Reason: "left company",
	})
	if err != nil {
		t.Fatalf("deactivate work profile failed: %v", err)
	}
	if result.Details.WorkProfile.Status != models.WorkProfileStatusInactive {
		t.Fatalf("expected INACTIVE, got %s", result.Details.WorkProfile.Status)
	}
	if result.Details.WorkProfile.DeactivatedAt == nil {
		t.Fatal("expected deactivated_at")
	}
}
