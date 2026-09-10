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

type ScheduleServiceStruct struct {
	repo *repository.Repo
	log  *zap.Logger
}

func NewScheduleServiceStruct(repo *repository.Repo, log *zap.Logger) *ScheduleServiceStruct {
	return &ScheduleServiceStruct{
		repo: repo,
		log:  log,
	}
}

func (s *ScheduleServiceStruct) SetBrigadeSchedule(ctx context.Context, in *models.SetBrigadeScheduleInput) (*models.SetBrigadeScheduleResult, error) {
	log := s.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("SetBrigadeSchedule")

	if err := in.Validate(); err != nil {
		log.Warn("SetBrigadeSchedule validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: SetBrigadeSchedule validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := s.getBrigadeForScheduleOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "SetBrigadeSchedule")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := s.repo.SetBrigadeSchedule(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: SetBrigadeSchedule: %w", err)
	}

	log.Info("SetBrigadeSchedule success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (s *ScheduleServiceStruct) ListBrigadeSchedule(ctx context.Context, in *models.ListBrigadeScheduleInput) (*models.ListBrigadeScheduleResult, error) {
	log := s.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("ListBrigadeSchedule")

	if err := in.Validate(); err != nil {
		log.Warn("ListBrigadeSchedule validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListBrigadeSchedule validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := s.getBrigadeForScheduleOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "ListBrigadeSchedule")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		// A worker may read the schedule of the brigade they actively belong to.
		// Schedule modification remains restricted to an admin or dispatcher.
		if in.ActorUserID == nil {
			return nil, err
		}
		own, ownErr := s.repo.GetBrigadeByUserID(ctx, &models.GetBrigadeByUserIDInput{UserID: *in.ActorUserID, OnlyActive: true})
		if ownErr != nil || own == nil || own.Brigade == nil || own.Brigade.ID != brigade.ID {
			return nil, err
		}
	}

	result, err := s.repo.ListBrigadeSchedule(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ListBrigadeSchedule: %w", err)
	}

	log.Info("ListBrigadeSchedule success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (s *ScheduleServiceStruct) getBrigadeForScheduleOperation(
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
