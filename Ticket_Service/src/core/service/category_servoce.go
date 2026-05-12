package service

import (
	"context"
	"fmt"

	"ticket/models"
	"ticket/src/core/repository"
)

type CategoryServiceStruct struct {
	repo *repository.Repository
}

func NewCategoryServiceStruct(repo *repository.Repository) *CategoryServiceStruct {
	return &CategoryServiceStruct{
		repo: repo,
	}
}

func (s *CategoryServiceStruct) CreateCategory(
	ctx context.Context,
	in models.CreateCategoryInput,
) (*models.CreateCategoryResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: CreateCategory(): validate: %w", err)
	}

	category, err := s.repo.CreateCategory(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: CreateCategory(): %w", err)
	}

	return &models.CreateCategoryResult{
		Category: category,
	}, nil
}

func (s *CategoryServiceStruct) GetCategory(
	ctx context.Context,
	in models.GetCategoryInput,
) (*models.GetCategoryResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: GetCategory(): validate: %w", err)
	}

	category, err := s.repo.GetCategoryByID(ctx, in.CategoryID)
	if err != nil {
		return nil, fmt.Errorf("service: GetCategory(): %w", err)
	}

	return &models.GetCategoryResult{
		Category: category,
	}, nil
}

func (s *CategoryServiceStruct) ListCategories(
	ctx context.Context,
	in models.ListCategoriesInput,
) (*models.ListCategoriesResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: ListCategories(): validate: %w", err)
	}

	categories, total, err := s.repo.ListCategories(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ListCategories(): %w", err)
	}

	return &models.ListCategoriesResult{
		Categories: categories,
		Total:      total,
	}, nil
}

func (s *CategoryServiceStruct) UpdateCategory(
	ctx context.Context,
	in models.UpdateCategoryInput,
) (*models.UpdateCategoryResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: UpdateCategory(): validate: %w", err)
	}

	category, err := s.repo.UpdateCategory(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: UpdateCategory(): %w", err)
	}

	return &models.UpdateCategoryResult{
		Category: category,
	}, nil
}

func (s *CategoryServiceStruct) DeleteCategory(
	ctx context.Context,
	in models.DeleteCategoryInput,
) (*models.DeleteCategoryResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: DeleteCategory(): validate: %w", err)
	}

	category, err := s.repo.DeleteCategory(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: DeleteCategory(): %w", err)
	}

	return &models.DeleteCategoryResult{
		Category: category,
	}, nil
}
