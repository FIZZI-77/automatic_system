package service

import (
	"brigade/models"
	"brigade/pkg"
	"brigade/src/core/repository"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type SkillServiceStruct struct {
	repo *repository.Repo
	log  *zap.Logger
}

func NewSkillServiceStruct(repo *repository.Repo, log *zap.Logger) *SkillServiceStruct {
	return &SkillServiceStruct{
		repo: repo,
		log:  log,
	}
}

func (s *SkillServiceStruct) CreateSkill(ctx context.Context, in *models.CreateSkillInput) (*models.CreateSkillResult, error) {
	log := s.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("CreateSkill")

	if err := in.Validate(); err != nil {
		log.Warn("CreateSkill validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CreateSkill validation failed: %w: %v", models.ErrValidation, err)
	}

	if err := checkAdminRole(log, start, in.ActorRoles); err != nil {
		return nil, err
	}

	result, err := s.repo.CreateSkill(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: CreateSkill: %w", err)
	}

	log.Info("CreateSkill success",
		zap.String("code", in.Code),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (s *SkillServiceStruct) UpdateSkill(ctx context.Context, in *models.UpdateSkillInput) (*models.UpdateSkillResult, error) {
	log := s.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("UpdateSkill")

	if err := in.Validate(); err != nil {
		log.Warn("UpdateSkill validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: UpdateSkill validation failed: %w: %v", models.ErrValidation, err)
	}

	if err := checkAdminRole(log, start, in.ActorRoles); err != nil {
		return nil, err
	}

	result, err := s.repo.UpdateSkill(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: UpdateSkill: %w", err)
	}

	log.Info("UpdateSkill success",
		zap.String("skill_id", in.ID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (s *SkillServiceStruct) DeactivateSkill(ctx context.Context, in *models.DeactivateSkillInput) (*models.DeactivateSkillResult, error) {
	log := s.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("DeactivateSkill")

	if err := in.Validate(); err != nil {
		log.Warn("DeactivateSkill validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: DeactivateSkill validation failed: %w: %v", models.ErrValidation, err)
	}

	if err := checkAdminRole(log, start, in.ActorRoles); err != nil {
		return nil, err
	}

	result, err := s.repo.DeactivateSkill(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: DeactivateSkill: %w", err)
	}

	log.Info("DeactivateSkill success",
		zap.String("skill_id", in.ID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (s *SkillServiceStruct) ListSkills(ctx context.Context, in *models.ListSkillsInput) (*models.ListSkillsResult, error) {
	log := s.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("ListSkills")

	if err := in.Validate(); err != nil {
		log.Warn("ListSkills validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListSkills validation failed: %w: %v", models.ErrValidation, err)
	}

	if err := checkAdminOrDispatcherRole(log, start, in.ActorRoles); err != nil {
		return nil, err
	}

	result, err := s.repo.ListSkills(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ListSkills: %w", err)
	}

	log.Info("ListSkills success",
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (s *SkillServiceStruct) AddBrigadeSkill(ctx context.Context, in *models.AddBrigadeSkillInput) (*models.AddBrigadeSkillResult, error) {
	log := s.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("AddBrigadeSkill")

	if err := in.Validate(); err != nil {
		log.Warn("AddBrigadeSkill validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: AddBrigadeSkill validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := s.getBrigadeForSkillOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "AddBrigadeSkill")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := s.repo.AddBrigadeSkill(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: AddBrigadeSkill: %w", err)
	}

	log.Info("AddBrigadeSkill success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.String("skill_id", in.SkillID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (s *SkillServiceStruct) RemoveBrigadeSkill(ctx context.Context, in *models.RemoveBrigadeSkillInput) (*models.RemoveBrigadeSkillResult, error) {
	log := s.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("RemoveBrigadeSkill")

	if err := in.Validate(); err != nil {
		log.Warn("RemoveBrigadeSkill validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: RemoveBrigadeSkill validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := s.getBrigadeForSkillOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "RemoveBrigadeSkill")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := s.repo.RemoveBrigadeSkill(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: RemoveBrigadeSkill: %w", err)
	}

	log.Info("RemoveBrigadeSkill success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.String("skill_id", in.SkillID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (s *SkillServiceStruct) ListBrigadeSkills(ctx context.Context, in *models.ListBrigadeSkillsInput) (*models.ListBrigadeSkillsResult, error) {
	log := s.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("ListBrigadeSkills")

	if err := in.Validate(); err != nil {
		log.Warn("ListBrigadeSkills validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListBrigadeSkills validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := s.getBrigadeForSkillOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "ListBrigadeSkills")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := s.repo.ListBrigadeSkills(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ListBrigadeSkills: %w", err)
	}

	log.Info("ListBrigadeSkills success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (s *SkillServiceStruct) getBrigadeForSkillOperation(
	ctx context.Context,
	log *zap.Logger,
	start time.Time,
	brigadeID uuid.UUID,
	actorUserID *uuid.UUID,
	actorDepartmentID *uuid.UUID,
	actorRoles []string,
	operation string,
) (*models.Brigade, error) {
	brigade, err := s.repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{
		ID:                brigadeID,
		ActorUserID:       actorUserID,
		ActorDepartmentID: actorDepartmentID,
		ActorRoles:        actorRoles,
	})
	if err != nil {
		return nil, fmt.Errorf("service: %s: get brigade: %w", operation, err)
	}

	if brigade.Brigade.Status == models.BrigadeStatusArchived {
		err = models.ErrPermissionDenied
		log.Warn(operation+" failed: brigade archived",
			zap.String("brigade_id", brigadeID.String()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, err
	}

	return brigade.Brigade, nil
}

func checkAdminRole(log *zap.Logger, start time.Time, actorRoles []string) error {
	for _, role := range actorRoles {
		if role == "admin" {
			return nil
		}
	}

	err := models.ErrPermissionDenied
	log.Warn("actor_role is not admin",
		zap.Int64("duration", time.Since(start).Milliseconds()),
		zap.Error(err),
	)
	return err
}

func checkAdminOrDispatcherRole(log *zap.Logger, start time.Time, actorRoles []string) error {
	for _, role := range actorRoles {
		if role == "admin" || role == "dispatcher" {
			return nil
		}
	}

	err := models.ErrPermissionDenied
	log.Warn("actor_role is not admin or dispatcher",
		zap.Int64("duration", time.Since(start).Milliseconds()),
		zap.Error(err),
	)
	return err
}
