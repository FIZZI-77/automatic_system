package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"ticket/models"
	"ticket/src/core/repository"
)

type mockCategoryRepo struct {
	createCategoryFunc  func(ctx context.Context, in *models.CreateCategoryInput) (*models.TicketCategory, error)
	getCategoryByIDFunc func(ctx context.Context, categoryID uuid.UUID) (*models.TicketCategory, error)
	listCategoriesFunc  func(ctx context.Context, in *models.ListCategoriesInput) ([]*models.TicketCategory, int64, error)
	updateCategoryFunc  func(ctx context.Context, in *models.UpdateCategoryInput) (*models.TicketCategory, error)
	deleteCategoryFunc  func(ctx context.Context, in *models.DeleteCategoryInput) (*models.TicketCategory, error)
}

func (m *mockCategoryRepo) CreateCategory(ctx context.Context, in *models.CreateCategoryInput) (*models.TicketCategory, error) {
	return m.createCategoryFunc(ctx, in)
}

func (m *mockCategoryRepo) GetCategoryByID(ctx context.Context, categoryID uuid.UUID) (*models.TicketCategory, error) {
	return m.getCategoryByIDFunc(ctx, categoryID)
}

func (m *mockCategoryRepo) ListCategories(ctx context.Context, in *models.ListCategoriesInput) ([]*models.TicketCategory, int64, error) {
	return m.listCategoriesFunc(ctx, in)
}

func (m *mockCategoryRepo) UpdateCategory(ctx context.Context, in *models.UpdateCategoryInput) (*models.TicketCategory, error) {
	return m.updateCategoryFunc(ctx, in)
}

func (m *mockCategoryRepo) DeleteCategory(ctx context.Context, in *models.DeleteCategoryInput) (*models.TicketCategory, error) {
	return m.deleteCategoryFunc(ctx, in)
}

func newTestCategoryService(repo *repository.Repository) *CategoryServiceStruct {
	return NewCategoryServiceStruct(repo, zap.NewNop())
}

func TestCategoryService_CreateCategory_Success(t *testing.T) {
	categoryID := uuid.New()
	description := "Water problems"

	categoryRepo := &mockCategoryRepo{
		createCategoryFunc: func(ctx context.Context, in *models.CreateCategoryInput) (*models.TicketCategory, error) {
			if in.Code != "water" {
				t.Fatalf("expected code water, got %s", in.Code)
			}

			if in.Name != "Water" {
				t.Fatalf("expected name Water, got %s", in.Name)
			}

			if in.Description == nil || *in.Description != description {
				t.Fatal("expected description")
			}

			return &models.TicketCategory{
				ID:          categoryID,
				Code:        in.Code,
				Name:        in.Name,
				Description: *in.Description,
				IsActive:    true,
			}, nil
		},
	}

	repo := &repository.Repository{
		CategoryRepository: categoryRepo,
	}

	svc := newTestCategoryService(repo)

	result, err := svc.CreateCategory(context.Background(), &models.CreateCategoryInput{
		Code:        "water",
		Name:        "Water",
		Description: &description,
		ActorRoles:  []string{"admin"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.Category.ID != categoryID {
		t.Fatalf("expected category id %s, got %s", categoryID, result.Category.ID)
	}
}

func TestCategoryService_UpdateCategory_PassesExplicitFalseIsActive(t *testing.T) {
	categoryID := uuid.New()
	isActive := false

	categoryRepo := &mockCategoryRepo{
		updateCategoryFunc: func(ctx context.Context, in *models.UpdateCategoryInput) (*models.TicketCategory, error) {
			if in.CategoryID != categoryID {
				t.Fatalf("expected category id %s, got %s", categoryID, in.CategoryID)
			}

			if in.IsActive == nil {
				t.Fatal("expected is_active pointer")
			}

			if *in.IsActive {
				t.Fatal("expected explicit is_active false")
			}

			return &models.TicketCategory{
				ID:       categoryID,
				Code:     "water",
				Name:     "Water",
				IsActive: false,
			}, nil
		},
	}

	repo := &repository.Repository{
		CategoryRepository: categoryRepo,
	}

	svc := newTestCategoryService(repo)

	result, err := svc.UpdateCategory(context.Background(), &models.UpdateCategoryInput{
		CategoryID: categoryID,
		IsActive:   &isActive,
		ActorRoles: []string{"dispatcher"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.Category.IsActive {
		t.Fatal("expected category inactive")
	}
}

func TestCategoryService_UpdateCategory_InvalidInputWrapsValidation(t *testing.T) {
	repo := &repository.Repository{
		CategoryRepository: &mockCategoryRepo{},
	}

	svc := newTestCategoryService(repo)

	result, err := svc.UpdateCategory(context.Background(), &models.UpdateCategoryInput{
		CategoryID: uuid.New(),
	})

	if result != nil {
		t.Fatal("expected nil result")
	}

	if !errors.Is(err, models.ErrValidation) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestCategoryService_CreateCategory_PreservesAlreadyExistsError(t *testing.T) {
	categoryRepo := &mockCategoryRepo{
		createCategoryFunc: func(ctx context.Context, in *models.CreateCategoryInput) (*models.TicketCategory, error) {
			return nil, models.ErrAlreadyExists
		},
	}

	repo := &repository.Repository{
		CategoryRepository: categoryRepo,
	}

	svc := newTestCategoryService(repo)

	result, err := svc.CreateCategory(context.Background(), &models.CreateCategoryInput{
		Code:       "water",
		Name:       "Water",
		ActorRoles: []string{"admin"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}

	if !errors.Is(err, models.ErrAlreadyExists) {
		t.Fatalf("expected already exists error, got %v", err)
	}
}

func TestCategoryService_ListCategories_NormalizesPagination(t *testing.T) {
	categoryID := uuid.New()

	categoryRepo := &mockCategoryRepo{
		listCategoriesFunc: func(ctx context.Context, in *models.ListCategoriesInput) ([]*models.TicketCategory, int64, error) {
			if in.Limit != models.DefaultLimit {
				t.Fatalf("expected default limit %d, got %d", models.DefaultLimit, in.Limit)
			}

			if in.Offset != 0 {
				t.Fatalf("expected offset 0, got %d", in.Offset)
			}

			return []*models.TicketCategory{{ID: categoryID, Code: "water", Name: "Water", IsActive: true}}, 1, nil
		},
	}

	repo := &repository.Repository{
		CategoryRepository: categoryRepo,
	}

	svc := newTestCategoryService(repo)

	result, err := svc.ListCategories(context.Background(), &models.ListCategoriesInput{
		Limit:  -1,
		Offset: -10,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.Total != 1 {
		t.Fatalf("expected total 1, got %d", result.Total)
	}

	if len(result.Categories) != 1 {
		t.Fatalf("expected 1 category, got %d", len(result.Categories))
	}
}

func TestCategoryService_DeleteCategory_Success(t *testing.T) {
	categoryID := uuid.New()

	categoryRepo := &mockCategoryRepo{
		deleteCategoryFunc: func(ctx context.Context, in *models.DeleteCategoryInput) (*models.TicketCategory, error) {
			if in.CategoryID != categoryID {
				t.Fatalf("expected category id %s, got %s", categoryID, in.CategoryID)
			}

			return &models.TicketCategory{
				ID:       categoryID,
				Code:     "water",
				Name:     "Water",
				IsActive: false,
			}, nil
		},
	}

	repo := &repository.Repository{
		CategoryRepository: categoryRepo,
	}

	svc := newTestCategoryService(repo)

	result, err := svc.DeleteCategory(context.Background(), &models.DeleteCategoryInput{
		CategoryID: categoryID,
		ActorRoles: []string{"admin"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.Category.IsActive {
		t.Fatal("expected inactive category")
	}
}

func TestCategoryService_MutationRequiresPrivilegedRole(t *testing.T) {
	t.Run("create category denied for regular user", func(t *testing.T) {
		svc := newTestCategoryService(&repository.Repository{CategoryRepository: &mockCategoryRepo{
			createCategoryFunc: func(ctx context.Context, in *models.CreateCategoryInput) (*models.TicketCategory, error) {
				t.Fatal("expected repo not to be called")
				return nil, nil
			},
		}})

		result, err := svc.CreateCategory(context.Background(), &models.CreateCategoryInput{
			Code:       "water",
			Name:       "Water",
			ActorRoles: []string{"user"},
		})

		if result != nil {
			t.Fatal("expected nil result")
		}

		if !errors.Is(err, models.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("delete category denied without role", func(t *testing.T) {
		svc := newTestCategoryService(&repository.Repository{CategoryRepository: &mockCategoryRepo{
			deleteCategoryFunc: func(ctx context.Context, in *models.DeleteCategoryInput) (*models.TicketCategory, error) {
				t.Fatal("expected repo not to be called")
				return nil, nil
			},
		}})

		result, err := svc.DeleteCategory(context.Background(), &models.DeleteCategoryInput{
			CategoryID: uuid.New(),
		})

		if result != nil {
			t.Fatal("expected nil result")
		}

		if !errors.Is(err, models.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})
}
