package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"department/models"
)

func TestDepartmentRepository_CreateGetListUpdateDelete(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(db)
	ctx := context.Background()

	created, err := repo.CreateDepartment(ctx, &models.CreateDepartmentInput{
		Name:        "Roads",
		Description: "Road maintenance",
	})
	if err != nil {
		t.Fatalf("create department failed: %v", err)
	}
	if created.ID.String() == "" {
		t.Fatal("expected department id")
	}
	if created.Status != models.DepartmentStatusActive {
		t.Fatalf("expected active status, got %s", created.Status)
	}

	found, err := repo.GetDepartmentByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("get department failed: %v", err)
	}
	if found.Name != "Roads" {
		t.Fatalf("expected Roads, got %s", found.Name)
	}

	list, total, err := repo.ListDepartments(ctx, &models.ListDepartmentsInput{
		SortBy:    models.DepartmentSortByName,
		SortOrder: models.SortOrderAsc,
		Limit:     10,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list departments failed: %v", err)
	}
	if total != 1 || len(list) != 1 {
		t.Fatalf("expected one department, got total=%d len=%d", total, len(list))
	}

	name := "Water"
	statusValue := models.DepartmentStatusInactive
	updated, err := repo.UpdateDepartment(ctx, &models.UpdateDepartmentInput{
		ID:     created.ID,
		Name:   &name,
		Status: &statusValue,
	})
	if err != nil {
		t.Fatalf("update department failed: %v", err)
	}
	if updated.Name != name || updated.Status != models.DepartmentStatusInactive {
		t.Fatalf("unexpected updated department: %#v", updated)
	}

	deleted, err := repo.DeleteDepartment(ctx, &models.DeleteDepartmentInput{ID: created.ID})
	if err != nil {
		t.Fatalf("delete department failed: %v", err)
	}
	if deleted.Status != models.DepartmentStatusArchived {
		t.Fatalf("expected archived status, got %s", deleted.Status)
	}
}

func TestDepartmentRepository_CreateDuplicateName(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(db)
	ctx := context.Background()

	_, err := repo.CreateDepartment(ctx, &models.CreateDepartmentInput{Name: "Roads"})
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	_, err = repo.CreateDepartment(ctx, &models.CreateDepartmentInput{Name: "Roads"})
	if !errors.Is(err, models.ErrAlreadyExists) {
		t.Fatalf("expected already exists, got %v", err)
	}
}

func TestDepartmentRepository_ListFilters(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(db)
	ctx := context.Background()

	active := createTestDepartment(t, repo)
	archived := createTestDepartment(t, repo)
	_, err := repo.DeleteDepartment(ctx, &models.DeleteDepartmentInput{ID: archived.ID})
	if err != nil {
		t.Fatalf("archive department failed: %v", err)
	}

	statusValue := models.DepartmentStatusActive
	list, total, err := repo.ListDepartments(ctx, &models.ListDepartmentsInput{
		Status:    &statusValue,
		SortBy:    models.DepartmentSortByCreatedAt,
		SortOrder: models.SortOrderDesc,
		Limit:     10,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list active departments failed: %v", err)
	}
	if total != 1 || len(list) != 1 || list[0].ID != active.ID {
		t.Fatalf("expected only active department, got total=%d list=%#v", total, list)
	}

	future := time.Now().Add(time.Hour)
	empty, total, err := repo.ListDepartments(ctx, &models.ListDepartmentsInput{
		CreatedFrom: &future,
		Limit:       10,
	})
	if err != nil {
		t.Fatalf("list by future date failed: %v", err)
	}
	if total != 0 || len(empty) != 0 {
		t.Fatalf("expected empty list, got total=%d len=%d", total, len(empty))
	}
}

func TestDepartmentRepository_OutboxEventsCreated(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(db)
	ctx := context.Background()

	department := createTestDepartment(t, repo)
	name := "Updated " + department.Name
	if _, err := repo.UpdateDepartment(ctx, &models.UpdateDepartmentInput{ID: department.ID, Name: &name}); err != nil {
		t.Fatalf("update failed: %v", err)
	}
	if _, err := repo.DeleteDepartment(ctx, &models.DeleteDepartmentInput{ID: department.ID}); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox_events WHERE aggregate_id = $1`, department.ID).Scan(&count)
	if err != nil {
		t.Fatalf("count outbox events failed: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 outbox events, got %d", count)
	}
}
