package service

import (
	"brigade/models"
	"brigade/pkg"
	"brigade/src/core/repository"
	"context"
	"errors"
	"fmt"
	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"time"
)

type BrigadeServiceStruct struct {
	repo             repository.Repo
	departmentClient departmentv1.DepartmentServiceClient
	logger           *zap.Logger
}

func NewBrigadeService(repo repository.Repo, departmentClient departmentv1.DepartmentServiceClient, logger *zap.Logger) *BrigadeServiceStruct {
	return &BrigadeServiceStruct{
		repo:             repo,
		departmentClient: departmentClient,
		logger:           logger,
	}
}

func (b *BrigadeServiceStruct) CreateBrigade(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error) {
	logger := b.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("CreateBrigade")

	if err := in.Validate(); err != nil {
		logger.Warn("CreateBrigade validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CreateBrigade validation failed: %w: %v", models.ErrValidation, err)
	}

	if err := checkPermissionAndDepartmentForAdminAndDispatcher(logger, start, in.ActorRoles, in.ActorDepartmentID, in.DepartmentID); err != nil {
		return nil, err
	}

	department, err := b.departmentClient.GetDepartmentByID(ctx, &departmentv1.GetDepartmentByIDRequest{
		Id: in.DepartmentID.String(),
	})

	if err != nil {
		return nil, fmt.Errorf("service: CreateBrigade: check department: %w", err)
	}

	departmentData := department.GetDepartment()
	if departmentData == nil || departmentData.Status != departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ACTIVE {
		err = errors.New("service: CreateBrigade error: department is not active")
		logger.Warn("CreateBrigade error: department is not active",
			zap.String("name", in.Name),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, err
	}

	result, err := b.repo.CreateBrigade(ctx, in)
	if err != nil {
		if errors.Is(err, models.ErrAlreadyExists) {
			logger.Warn("CreateBrigade error: Brigade already exists",
				zap.String("name", in.Name),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, fmt.Errorf("service: CreateBrigade error: Brigade already exists: %w", err)
		}
		return nil, fmt.Errorf("service: CreateBrigade error: %w", err)
	}

	logger.Info("CreateBrigade success",
		zap.String("name", in.Name),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) GetBrigadeByID(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error) {
	logger := b.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("GetBrigadeByID")

	if err := in.Validate(); err != nil {
		logger.Warn("GetBrigadeByID validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetBrigadeByID validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := b.repo.GetBrigadeByID(ctx, in)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			logger.Warn("GetBrigadeByID: Brigade not found",
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: GetBrigadeByID: Brigade error: %w", err)
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(logger, start, in.ActorRoles, in.ActorDepartmentID, brigade.Brigade.DepartmentID); err != nil {
		return nil, err
	}

	logger.Info("GetBrigadeByID success",
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return brigade, nil

}

func (b *BrigadeServiceStruct) ListBrigades(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error) {
	logger := b.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("ListBrigades")

	if err := in.Validate(); err != nil {
		logger.Warn("ListBrigades validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListBrigades validation failed: %w: %v", models.ErrValidation, err)
	}

	isAdmin := false
	isDispatcher := false

	for _, role := range in.ActorRoles {
		if role == "admin" {
			isAdmin = true
		}
		if role == "dispatcher" {
			isDispatcher = true
		}
	}

	if !isAdmin && !isDispatcher {
		err := models.ErrPermissionDenied
		logger.Warn("ListBrigades error: actor is not admin or dispatcher",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, err
	}

	if !isAdmin {
		if in.ActorDepartmentID == nil {
			err := models.ErrPermissionDenied
			logger.Warn("ListBrigades error: actor_department is nil",
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		in.DepartmentID = in.ActorDepartmentID
	}

	result, err := b.repo.ListBrigades(ctx, in)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			logger.Warn("ListBrigades: Brigade not found",
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: ListBrigades error: %w", err)
	}
	logger.Info("ListBrigades success",
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) UpdateBrigade(ctx context.Context, in *models.UpdateBrigadeInput) (*models.UpdateBrigadeResult, error) {
	logger := b.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("UpdateBrigade")

	if err := in.Validate(); err != nil {
		logger.Warn("UpdateBrigade validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: UpdateBrigade validation failed: %w: %v", models.ErrValidation, err)
	}

	current, err := b.repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{ID: in.ID})
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			logger.Warn("UpdateBrigade: Brigade not found",
				zap.String("brigade_id", in.ID.String()),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: UpdateBrigade: get brigade: %w", err)
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(logger, start, in.ActorRoles, in.ActorDepartmentID, current.Brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := b.repo.UpdateBrigade(ctx, in)
	if err != nil {
		if errors.Is(err, models.ErrAlreadyExists) {
			logger.Warn("UpdateBrigade error: Brigade already exists",
				zap.String("brigade_id", in.ID.String()),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, fmt.Errorf("service: UpdateBrigade error: Brigade already exists: %w", err)
		}
		return nil, fmt.Errorf("service: UpdateBrigade error: %w", err)
	}

	logger.Info("UpdateBrigade success",
		zap.String("brigade_id", in.ID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) DeactivateBrigade(ctx context.Context, in *models.DeactivateBrigadeInput) (*models.DeactivateBrigadeResult, error) {
	logger := b.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("DeactivateBrigade")

	if err := in.Validate(); err != nil {
		logger.Warn("DeactivateBrigade validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: DeactivateBrigade validation failed: %w: %v", models.ErrValidation, err)
	}

	current, err := b.repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{ID: in.ID})
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			logger.Warn("DeactivateBrigade: Brigade not found",
				zap.String("brigade_id", in.ID.String()),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: DeactivateBrigade: get brigade: %w: %v", models.ErrValidation, err)
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(logger, start, in.ActorRoles, in.ActorDepartmentID, current.Brigade.DepartmentID); err != nil {
		return nil, err
	}

	if in.ChangedByUserID == nil {
		in.ChangedByUserID = in.ActorUserID
	}

	result, err := b.repo.DeactivateBrigade(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: DeactivateBrigade error: %w", err)
	}

	logger.Info("DeactivateBrigade success",
		zap.String("brigade_id", in.ID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) ArchiveBrigade(ctx context.Context, in *models.ArchiveBrigadeInput) (*models.ArchiveBrigadeResult, error) {
	logger := b.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("ArchiveBrigade")

	if err := in.Validate(); err != nil {
		logger.Warn("ArchiveBrigade validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ArchiveBrigade validation failed: %w: %v", models.ErrValidation, err)
	}

	current, err := b.repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{ID: in.ID})
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			logger.Warn("ArchiveBrigade: Brigade not found",
				zap.String("brigade_id", in.ID.String()),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: ArchiveBrigade: get brigade: %w", err)
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(logger, start, in.ActorRoles, in.ActorDepartmentID, current.Brigade.DepartmentID); err != nil {
		return nil, err
	}

	if in.ChangedByUserID == nil {
		in.ChangedByUserID = in.ActorUserID
	}

	result, err := b.repo.ArchiveBrigade(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ArchiveBrigade error: %w", err)
	}

	logger.Info("ArchiveBrigade success",
		zap.String("brigade_id", in.ID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) SetBrigadeStatus(ctx context.Context, in *models.SetBrigadeStatusInput) (*models.SetBrigadeStatusResult, error) {
	logger := b.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("SetBrigadeStatus")

	if err := in.Validate(); err != nil {
		logger.Warn("SetBrigadeStatus validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: SetBrigadeStatus validation failed: %w: %v", models.ErrValidation, err)
	}

	current, err := b.repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{ID: in.BrigadeID})
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			logger.Warn("SetBrigadeStatus: Brigade not found",
				zap.String("brigade_id", in.BrigadeID.String()),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: SetBrigadeStatus: get brigade: %w", err)
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(logger, start, in.ActorRoles, in.ActorDepartmentID, current.Brigade.DepartmentID); err != nil {
		return nil, err
	}

	if in.ChangedByUserID == nil {
		in.ChangedByUserID = in.ActorUserID
	}

	result, err := b.repo.SetBrigadeStatus(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: SetBrigadeStatus error: %w", err)
	}

	logger.Info("SetBrigadeStatus success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.String("status", string(in.Status)),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) GetBrigadeStatusHistory(ctx context.Context, in *models.GetBrigadeStatusHistoryInput) (*models.GetBrigadeStatusHistoryResult, error) {
	logger := b.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("GetBrigadeStatusHistory")

	if err := in.Validate(); err != nil {
		logger.Warn("GetBrigadeStatusHistory validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetBrigadeStatusHistory validation failed: %w: %v", models.ErrValidation, err)
	}

	current, err := b.repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{ID: in.BrigadeID})
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			logger.Warn("GetBrigadeStatusHistory: Brigade not found",
				zap.String("brigade_id", in.BrigadeID.String()),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: GetBrigadeStatusHistory: get brigade: %w", err)
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(logger, start, in.ActorRoles, in.ActorDepartmentID, current.Brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := b.repo.GetBrigadeStatusHistory(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: GetBrigadeStatusHistory error: %w", err)
	}

	logger.Info("GetBrigadeStatusHistory success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) GetAvailableBrigades(ctx context.Context, in *models.GetAvailableBrigadesInput) (*models.GetAvailableBrigadesResult, error) {
	logger := b.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("GetAvailableBrigades")

	if err := in.Validate(); err != nil {
		logger.Warn("GetAvailableBrigades validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetAvailableBrigades validation failed: %w: %v", models.ErrValidation, err)
	}

	result, err := b.repo.GetAvailableBrigades(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: GetAvailableBrigades error: %w", err)
	}

	logger.Info("GetAvailableBrigades success",
		zap.String("department_id", in.DepartmentID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) CheckBrigadeCanHandleTicket(ctx context.Context, in *models.CheckBrigadeCanHandleTicketInput) (*models.CheckBrigadeCanHandleTicketResult, error) {
	logger := b.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("CheckBrigadeCanHandleTicket")

	if err := in.Validate(); err != nil {
		logger.Warn("CheckBrigadeCanHandleTicket validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CheckBrigadeCanHandleTicket validation failed: %w: %v", models.ErrValidation, err)
	}

	result, err := b.repo.CheckBrigadeCanHandleTicket(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: CheckBrigadeCanHandleTicket error: %w", err)
	}

	logger.Info("CheckBrigadeCanHandleTicket success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Bool("can_handle", result.CanHandle),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func checkPermissionAndDepartmentForAdminAndDispatcher(logger *zap.Logger, start time.Time, actorRoles []string, actorDepartmentID *uuid.UUID, departmentID uuid.UUID) error {
	if actorRoles == nil {
		logger.Warn("actor_roles is nil",
			zap.Int64("duration", time.Since(start).Milliseconds()),
		)
		return models.ErrPermissionDenied
	}

	access := false

	for _, role := range actorRoles {
		if role == "admin" {
			return nil
		}
		if role == "dispatcher" {
			access = true
		} else {
			continue
		}
	}

	if !access {
		err := models.ErrPermissionDenied
		logger.Warn("actor_role is not admin or dispatcher",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return err
	}

	if actorDepartmentID == nil {
		err := models.ErrPermissionDenied
		logger.Warn("actor_department is nil",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return err
	}

	if *actorDepartmentID != departmentID {
		err := models.ErrPermissionDenied
		logger.Warn("actor_department is not match",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return err
	}

	return nil

}
