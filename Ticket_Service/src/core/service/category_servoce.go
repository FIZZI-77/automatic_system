package service

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"ticket/models"
	"ticket/src/core/repository"
)

type CategoryServiceStruct struct {
	repo   *repository.Repository
	logger *zap.Logger
}

func NewCategoryServiceStruct(repo *repository.Repository, logger *zap.Logger) *CategoryServiceStruct {
	return &CategoryServiceStruct{
		repo:   repo,
		logger: logger,
	}
}

func (s *CategoryServiceStruct) CreateCategory(ctx context.Context, in *models.CreateCategoryInput) (*models.CreateCategoryResult, error) {
	start := time.Now()

	s.logger.Info("CreateCategory",
		zap.String("code", in.Code),
		zap.String("name", in.Name),
	)

	if err := in.Validate(); err != nil {
		s.logger.Warn("CreateCategory validation failed",
			zap.String("code", in.Code),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CreateCategory(): validate: %w", err)
	}

	category, err := s.repo.CreateCategory(ctx, in)
	if err != nil {
		s.logger.Error("CreateCategory failed",
			zap.String("code", in.Code),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CreateCategory(): %w", err)
	}

	s.logger.Info("CreateCategory success",
		zap.String("category_id", category.ID.String()),
		zap.String("code", category.Code),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.CreateCategoryResult{
		Category: category,
	}, nil
}

func (s *CategoryServiceStruct) GetCategory(ctx context.Context, in *models.GetCategoryInput) (*models.GetCategoryResult, error) {
	start := time.Now()

	s.logger.Info("GetCategory",
		zap.String("category_id", in.CategoryID.String()),
	)

	if err := in.Validate(); err != nil {
		s.logger.Warn("GetCategory validation failed",
			zap.String("category_id", in.CategoryID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetCategory(): validate: %w", err)
	}

	category, err := s.repo.GetCategoryByID(ctx, in.CategoryID)
	if err != nil {
		s.logger.Error("GetCategory failed",
			zap.String("category_id", in.CategoryID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetCategory(): %w", err)
	}

	s.logger.Info("GetCategory success",
		zap.String("category_id", category.ID.String()),
		zap.String("code", category.Code),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.GetCategoryResult{
		Category: category,
	}, nil
}

func (s *CategoryServiceStruct) ListCategories(ctx context.Context, in *models.ListCategoriesInput) (*models.ListCategoriesResult, error) {
	start := time.Now()

	s.logger.Info("ListCategories",
		zap.Bool("only_active", in.OnlyActive),
		zap.Int32("limit", in.Limit),
		zap.Int32("offset", in.Offset),
	)

	if err := in.Validate(); err != nil {
		s.logger.Warn("ListCategories validation failed",
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListCategories(): validate: %w", err)
	}

	categories, total, err := s.repo.ListCategories(ctx, in)
	if err != nil {
		s.logger.Error("ListCategories failed",
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListCategories(): %w", err)
	}

	s.logger.Info("ListCategories success",
		zap.Int("count", len(categories)),
		zap.Int64("total", total),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.ListCategoriesResult{
		Categories: categories,
		Total:      total,
	}, nil
}

func (s *CategoryServiceStruct) UpdateCategory(ctx context.Context, in *models.UpdateCategoryInput) (*models.UpdateCategoryResult, error) {
	start := time.Now()

	s.logger.Info("UpdateCategory",
		zap.String("category_id", in.CategoryID.String()),
	)

	if in.Name != nil {
		s.logger.Debug("UpdateCategory name", zap.String("name", *in.Name))
	}
	if in.IsActive != nil {
		s.logger.Debug("UpdateCategory is_active", zap.Bool("is_active", *in.IsActive))
	}

	if err := in.Validate(); err != nil {
		s.logger.Warn("UpdateCategory validation failed",
			zap.String("category_id", in.CategoryID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: UpdateCategory(): validate: %w", err)
	}

	category, err := s.repo.UpdateCategory(ctx, in)
	if err != nil {
		s.logger.Error("UpdateCategory failed",
			zap.String("category_id", in.CategoryID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: UpdateCategory(): %w", err)
	}

	s.logger.Info("UpdateCategory success",
		zap.String("category_id", category.ID.String()),
		zap.String("code", category.Code),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.UpdateCategoryResult{
		Category: category,
	}, nil
}

func (s *CategoryServiceStruct) DeleteCategory(ctx context.Context, in *models.DeleteCategoryInput) (*models.DeleteCategoryResult, error) {

	start := time.Now()

	s.logger.Info("DeleteCategory",
		zap.String("category_id", in.CategoryID.String()),
	)

	if err := in.Validate(); err != nil {
		s.logger.Warn("DeleteCategory validation failed",
			zap.String("category_id", in.CategoryID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: DeleteCategory(): validate: %w", err)
	}

	category, err := s.repo.DeleteCategory(ctx, in)
	if err != nil {
		s.logger.Error("DeleteCategory failed",
			zap.String("category_id", in.CategoryID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: DeleteCategory(): %w", err)
	}

	s.logger.Info("DeleteCategory success",
		zap.String("category_id", category.ID.String()),
		zap.String("code", category.Code),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.DeleteCategoryResult{
		Category: category,
	}, nil
}
