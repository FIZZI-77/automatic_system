package repository

import (
	"context"
	"errors"
	"testing"

	"ticket/models"
)

func TestCategoryRepo_CreateCategory_DuplicateCodeReturnsAlreadyExists(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(db)

	in := &models.CreateCategoryInput{
		Code:        "water",
		Name:        "Water",
		Description: stringPtr("Water problems"),
	}

	if _, err := repo.CreateCategory(ctx, in); err != nil {
		t.Fatalf("expected first create to succeed, got %v", err)
	}

	category, err := repo.CreateCategory(ctx, &models.CreateCategoryInput{
		Code:        "water",
		Name:        "Water Duplicate",
		Description: stringPtr("Duplicate category"),
	})

	if category != nil {
		t.Fatal("expected nil category")
	}

	if !errors.Is(err, models.ErrAlreadyExists) {
		t.Fatalf("expected already exists error, got %v", err)
	}
}

func TestCategoryRepo_UpdateCategory_NilIsActivePreservesValue(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(db)

	category := createTestCategory(t, repo)

	updated, err := repo.UpdateCategory(ctx, &models.UpdateCategoryInput{
		CategoryID: category.ID,
		Name:       stringPtr("Updated Category"),
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !updated.IsActive {
		t.Fatal("expected is_active to remain true")
	}

	if updated.Name != "Updated Category" {
		t.Fatalf("expected updated name, got %s", updated.Name)
	}
}

func TestCategoryRepo_ListCategories_FiltersOnlyActive(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(db)

	active := createTestCategory(t, repo)
	inactive := createTestCategory(t, repo)
	isActive := false

	_, err := repo.UpdateCategory(ctx, &models.UpdateCategoryInput{
		CategoryID: inactive.ID,
		IsActive:   &isActive,
	})
	if err != nil {
		t.Fatalf("failed to deactivate category: %v", err)
	}

	categories, total, err := repo.ListCategories(ctx, &models.ListCategoriesInput{
		OnlyActive: true,
		Limit:      10,
		Offset:     0,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if total != 1 {
		t.Fatalf("expected total 1, got %d", total)
	}

	if len(categories) != 1 {
		t.Fatalf("expected 1 category, got %d", len(categories))
	}

	if categories[0].ID != active.ID {
		t.Fatalf("expected active category %s, got %s", active.ID, categories[0].ID)
	}
}

func TestCategoryRepo_UpdateCategory_ExplicitFalseDeactivatesCategory(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(db)

	category := createTestCategory(t, repo)
	isActive := false

	updated, err := repo.UpdateCategory(ctx, &models.UpdateCategoryInput{
		CategoryID: category.ID,
		IsActive:   &isActive,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if updated.IsActive {
		t.Fatal("expected category inactive")
	}
}

func TestCategoryRepo_DeleteCategory_DeactivatesCategory(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(db)

	category := createTestCategory(t, repo)

	deleted, err := repo.DeleteCategory(ctx, &models.DeleteCategoryInput{
		CategoryID: category.ID,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if deleted.IsActive {
		t.Fatal("expected deleted category inactive")
	}

	stored, err := repo.GetCategoryByID(ctx, category.ID)
	if err != nil {
		t.Fatalf("failed to get category: %v", err)
	}

	if stored.IsActive {
		t.Fatal("expected stored category inactive")
	}
}
