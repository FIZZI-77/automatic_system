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

type ZoneServiceStruct struct {
	repo *repository.Repo
	log  *zap.Logger
}

func NewZoneServiceStruct(repo *repository.Repo, log *zap.Logger) *ZoneServiceStruct {
	return &ZoneServiceStruct{
		repo: repo,
		log:  log,
	}
}

func (z *ZoneServiceStruct) CreateBrigadeZone(ctx context.Context, in *models.CreateBrigadeZoneInput) (*models.CreateBrigadeZoneResult, error) {
	log := z.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("CreateBrigadeZone")

	if err := in.Validate(); err != nil {
		log.Warn("CreateBrigadeZone validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CreateBrigadeZone validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := z.getBrigadeForZoneOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "CreateBrigadeZone")
	if err != nil {
		return nil, err
	}

	if brigade.DepartmentID != in.DepartmentID {
		err = models.ErrPermissionDenied
		log.Warn("CreateBrigadeZone failed: brigade department mismatch",
			zap.String("brigade_id", in.BrigadeID.String()),
			zap.String("brigade_department_id", brigade.DepartmentID.String()),
			zap.String("zone_department_id", in.DepartmentID.String()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := z.repo.CreateBrigadeZone(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: CreateBrigadeZone: %w", err)
	}

	log.Info("CreateBrigadeZone success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (z *ZoneServiceStruct) UpdateBrigadeZone(ctx context.Context, in *models.UpdateBrigadeZoneInput) (*models.UpdateBrigadeZoneResult, error) {
	log := z.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("UpdateBrigadeZone")

	if err := in.Validate(); err != nil {
		log.Warn("UpdateBrigadeZone validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: UpdateBrigadeZone validation failed: %w: %v", models.ErrValidation, err)
	}

	zone, err := z.repo.GetBrigadeZoneByID(ctx, in.ID)
	if err != nil {
		return nil, fmt.Errorf("service: UpdateBrigadeZone: get zone: %w", err)
	}

	brigade, err := z.getBrigadeForZoneOperation(ctx, log, start, zone.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "UpdateBrigadeZone")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := z.repo.UpdateBrigadeZone(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: UpdateBrigadeZone: %w", err)
	}

	log.Info("UpdateBrigadeZone success",
		zap.String("zone_id", in.ID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (z *ZoneServiceStruct) DeleteBrigadeZone(ctx context.Context, in *models.DeleteBrigadeZoneInput) (*models.DeleteBrigadeZoneResult, error) {
	log := z.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("DeleteBrigadeZone")

	if err := in.Validate(); err != nil {
		log.Warn("DeleteBrigadeZone validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: DeleteBrigadeZone validation failed: %w: %v", models.ErrValidation, err)
	}

	zone, err := z.repo.GetBrigadeZoneByID(ctx, in.ID)
	if err != nil {
		return nil, fmt.Errorf("service: DeleteBrigadeZone: get zone: %w", err)
	}

	brigade, err := z.getBrigadeForZoneOperation(ctx, log, start, zone.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "DeleteBrigadeZone")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := z.repo.DeleteBrigadeZone(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: DeleteBrigadeZone: %w", err)
	}

	log.Info("DeleteBrigadeZone success",
		zap.String("zone_id", in.ID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (z *ZoneServiceStruct) ListBrigadeZones(ctx context.Context, in *models.ListBrigadeZonesInput) (*models.ListBrigadeZonesResult, error) {
	log := z.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("ListBrigadeZones")

	if err := in.Validate(); err != nil {
		log.Warn("ListBrigadeZones validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListBrigadeZones validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := z.getBrigadeForZoneOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "ListBrigadeZones")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := z.repo.ListBrigadeZones(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ListBrigadeZones: %w", err)
	}

	log.Info("ListBrigadeZones success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (z *ZoneServiceStruct) CheckBrigadeCoversPoint(ctx context.Context, in *models.CheckBrigadeCoversPointInput) (*models.CheckBrigadeCoversPointResult, error) {
	log := z.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("CheckBrigadeCoversPoint")

	if err := in.Validate(); err != nil {
		log.Warn("CheckBrigadeCoversPoint validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CheckBrigadeCoversPoint validation failed: %w: %v", models.ErrValidation, err)
	}

	result, err := z.repo.CheckBrigadeCoversPoint(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: CheckBrigadeCoversPoint: %w", err)
	}

	log.Info("CheckBrigadeCoversPoint success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Bool("covers", result.Covers),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (z *ZoneServiceStruct) FindBrigadesByPoint(ctx context.Context, in *models.FindBrigadesByPointInput) (*models.FindBrigadesByPointResult, error) {
	log := z.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("FindBrigadesByPoint")

	if err := in.Validate(); err != nil {
		log.Warn("FindBrigadesByPoint validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: FindBrigadesByPoint validation failed: %w: %v", models.ErrValidation, err)
	}

	result, err := z.repo.FindBrigadesByPoint(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: FindBrigadesByPoint: %w", err)
	}

	log.Info("FindBrigadesByPoint success",
		zap.String("department_id", in.DepartmentID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (z *ZoneServiceStruct) getBrigadeForZoneOperation(
	ctx context.Context,
	log *zap.Logger,
	start time.Time,
	brigadeID uuid.UUID,
	actorUserID *uuid.UUID,
	actorDepartmentID *uuid.UUID,
	actorRoles []string,
	operation string,
) (*models.Brigade, error) {
	brigade, err := z.repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{
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
