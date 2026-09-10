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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"math/rand/v2"
	"time"
)

const (
	departmentCheckAttempts       = 3
	departmentCheckTimeout        = 2 * time.Second
	departmentCheckInitialBackoff = 100 * time.Millisecond
	departmentCheckMaxJitter      = 50 * time.Millisecond
)

type BrigadeServiceStruct struct {
	repo             *repository.Repo
	departmentClient departmentv1.DepartmentServiceClient
	log              *zap.Logger
}

func NewBrigadeService(repo *repository.Repo, departmentClient departmentv1.DepartmentServiceClient, log *zap.Logger) *BrigadeServiceStruct {
	return &BrigadeServiceStruct{
		repo:             repo,
		departmentClient: departmentClient,
		log:              log,
	}
}

func (b *BrigadeServiceStruct) CreateBrigade(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error) {
	log := b.log.With(pkg.RequestIDField(ctx))
	start := time.Now()
	validationStart := time.Now()

	log.Info("CreateBrigade")

	if err := in.Validate(); err != nil {
		log.Warn("CreateBrigade validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CreateBrigade validation failed: %w: %v", models.ErrValidation, err)
	}
	validationMs := time.Since(validationStart).Milliseconds()

	permissionStart := time.Now()
	if err := checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, in.DepartmentID); err != nil {
		return nil, err
	}
	permissionCheckMs := time.Since(permissionStart).Milliseconds()

	departmentCheckStart := time.Now()
	department, err := b.getDepartmentByIDWithRetry(ctx, log, in.DepartmentID)
	departmentCheckMs := time.Since(departmentCheckStart).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("service: CreateBrigade: check department: %w", err)
	}

	departmentData := department.GetDepartment()
	if departmentData == nil || departmentData.Status != departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ACTIVE {
		err = models.ErrDepartmentInactive
		log.Warn("CreateBrigade error: department is not active",
			zap.String("name", in.Name),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Int64("validation_ms", validationMs),
			zap.Int64("permission_check_ms", permissionCheckMs),
			zap.Int64("department_check_ms", departmentCheckMs),
			zap.Error(err),
		)
		return nil, err
	}

	repoStart := time.Now()
	result, err := b.repo.CreateBrigade(ctx, in)
	repoMs := time.Since(repoStart).Milliseconds()
	if err != nil {
		if errors.Is(err, models.ErrAlreadyExists) {
			log.Warn("CreateBrigade error: Brigade already exists",
				zap.String("name", in.Name),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Int64("validation_ms", validationMs),
				zap.Int64("permission_check_ms", permissionCheckMs),
				zap.Int64("department_check_ms", departmentCheckMs),
				zap.Int64("repo_ms", repoMs),
				zap.Error(err),
			)
			return nil, fmt.Errorf("service: CreateBrigade error: Brigade already exists: %w", err)
		}
		return nil, fmt.Errorf("service: CreateBrigade error: %w", err)
	}

	log.Info("CreateBrigade success",
		zap.String("name", in.Name),
		zap.Int64("duration", time.Since(start).Milliseconds()),
		zap.Int64("validation_ms", validationMs),
		zap.Int64("permission_check_ms", permissionCheckMs),
		zap.Int64("department_check_ms", departmentCheckMs),
		zap.Int64("repo_ms", repoMs),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) getDepartmentByIDWithRetry(ctx context.Context, log *zap.Logger, departmentID uuid.UUID) (*departmentv1.GetDepartmentByIDResponse, error) {
	var lastErr error
	backoff := departmentCheckInitialBackoff

	for attempt := 1; attempt <= departmentCheckAttempts; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, departmentCheckTimeout)
		department, err := b.departmentClient.GetDepartmentByID(callCtx, &departmentv1.GetDepartmentByIDRequest{
			Id: departmentID.String(),
		})
		cancel()

		if err == nil {
			return department, nil
		}

		lastErr = err
		if !isRetryableDepartmentError(err) || attempt == departmentCheckAttempts {
			break
		}

		delay := backoff + time.Duration(rand.Int64N(int64(departmentCheckMaxJitter)))
		log.Warn("Department Service request failed, retrying",
			zap.String("department_id", departmentID.String()),
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", departmentCheckAttempts),
			zap.Duration("retry_after", delay),
			zap.String("grpc_code", status.Code(err).String()),
			zap.Error(err),
		)

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}

		backoff *= 2
	}

	return nil, mapDepartmentServiceError(lastErr)
}

func mapDepartmentServiceError(err error) error {
	if err == nil {
		return nil
	}

	switch status.Code(err) {
	case codes.NotFound:
		return fmt.Errorf("department service: %w", models.ErrNotFound)
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
		return fmt.Errorf("department service: %w: %v", models.ErrDependencyUnavailable, err)
	default:
		return err
	}
}

func isRetryableDepartmentError(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
		return true
	default:
		return false
	}
}

func (b *BrigadeServiceStruct) GetBrigadeByID(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error) {
	log := b.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("GetBrigadeByID")

	if err := in.Validate(); err != nil {
		log.Warn("GetBrigadeByID validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetBrigadeByID validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := b.repo.GetBrigadeByID(ctx, in)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			log.Warn("GetBrigadeByID: Brigade not found",
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: GetBrigadeByID: Brigade error: %w", err)
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.Brigade.DepartmentID); err != nil {
		// Workers may read only the brigade they actively belong to. This is
		// needed for the worker workspace and completion-report attribution.
		if in.ActorUserID == nil {
			return nil, err
		}
		own, ownErr := b.repo.GetBrigadeByUserID(ctx, &models.GetBrigadeByUserIDInput{UserID: *in.ActorUserID, OnlyActive: true})
		if ownErr != nil || own == nil || own.Brigade == nil || own.Brigade.ID != brigade.Brigade.ID {
			return nil, err
		}
	}

	log.Info("GetBrigadeByID success",
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return brigade, nil

}

func (b *BrigadeServiceStruct) ListBrigades(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error) {
	log := b.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("ListBrigades")

	if err := in.Validate(); err != nil {
		log.Warn("ListBrigades validation failed",
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
		log.Warn("ListBrigades error: actor is not admin or dispatcher",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, err
	}

	if !isAdmin {
		if in.ActorDepartmentID == nil {
			err := models.ErrPermissionDenied
			log.Warn("ListBrigades error: actor_department is nil",
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
			log.Warn("ListBrigades: Brigade not found",
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: ListBrigades error: %w", err)
	}
	log.Info("ListBrigades success",
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) UpdateBrigade(ctx context.Context, in *models.UpdateBrigadeInput) (*models.UpdateBrigadeResult, error) {
	log := b.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("UpdateBrigade")

	if err := in.Validate(); err != nil {
		log.Warn("UpdateBrigade validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: UpdateBrigade validation failed: %w: %v", models.ErrValidation, err)
	}

	current, err := b.repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{ID: in.ID})
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			log.Warn("UpdateBrigade: Brigade not found",
				zap.String("brigade_id", in.ID.String()),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: UpdateBrigade: get brigade: %w", err)
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, current.Brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := b.repo.UpdateBrigade(ctx, in)
	if err != nil {
		if errors.Is(err, models.ErrAlreadyExists) {
			log.Warn("UpdateBrigade error: Brigade already exists",
				zap.String("brigade_id", in.ID.String()),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, fmt.Errorf("service: UpdateBrigade error: Brigade already exists: %w", err)
		}
		return nil, fmt.Errorf("service: UpdateBrigade error: %w", err)
	}

	log.Info("UpdateBrigade success",
		zap.String("brigade_id", in.ID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) DeactivateBrigade(ctx context.Context, in *models.DeactivateBrigadeInput) (*models.DeactivateBrigadeResult, error) {
	log := b.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("DeactivateBrigade")

	if err := in.Validate(); err != nil {
		log.Warn("DeactivateBrigade validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: DeactivateBrigade validation failed: %w: %v", models.ErrValidation, err)
	}

	current, err := b.repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{ID: in.ID})
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			log.Warn("DeactivateBrigade: Brigade not found",
				zap.String("brigade_id", in.ID.String()),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: DeactivateBrigade: get brigade: %w: %v", models.ErrValidation, err)
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, current.Brigade.DepartmentID); err != nil {
		return nil, err
	}

	if in.ChangedByUserID == nil {
		in.ChangedByUserID = in.ActorUserID
	}

	result, err := b.repo.DeactivateBrigade(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: DeactivateBrigade error: %w", err)
	}

	log.Info("DeactivateBrigade success",
		zap.String("brigade_id", in.ID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) ArchiveBrigade(ctx context.Context, in *models.ArchiveBrigadeInput) (*models.ArchiveBrigadeResult, error) {
	log := b.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("ArchiveBrigade")

	if err := in.Validate(); err != nil {
		log.Warn("ArchiveBrigade validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ArchiveBrigade validation failed: %w: %v", models.ErrValidation, err)
	}

	current, err := b.repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{ID: in.ID})
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			log.Warn("ArchiveBrigade: Brigade not found",
				zap.String("brigade_id", in.ID.String()),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: ArchiveBrigade: get brigade: %w", err)
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, current.Brigade.DepartmentID); err != nil {
		return nil, err
	}

	if in.ChangedByUserID == nil {
		in.ChangedByUserID = in.ActorUserID
	}

	result, err := b.repo.ArchiveBrigade(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ArchiveBrigade error: %w", err)
	}

	log.Info("ArchiveBrigade success",
		zap.String("brigade_id", in.ID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) SetBrigadeStatus(ctx context.Context, in *models.SetBrigadeStatusInput) (*models.SetBrigadeStatusResult, error) {
	log := b.log.With(pkg.RequestIDField(ctx))
	start := time.Now()
	validationStart := time.Now()

	log.Info("SetBrigadeStatus")

	if err := in.Validate(); err != nil {
		log.Warn("SetBrigadeStatus validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: SetBrigadeStatus validation failed: %w: %v", models.ErrValidation, err)
	}
	validationMs := time.Since(validationStart).Milliseconds()

	getBrigadeStart := time.Now()
	current, err := b.repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{ID: in.BrigadeID})
	getBrigadeMs := time.Since(getBrigadeStart).Milliseconds()
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			log.Warn("SetBrigadeStatus: Brigade not found",
				zap.String("brigade_id", in.BrigadeID.String()),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Int64("validation_ms", validationMs),
				zap.Int64("get_brigade_ms", getBrigadeMs),
				zap.String("target_status", string(in.Status)),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: SetBrigadeStatus: get brigade: %w", err)
	}

	permissionStart := time.Now()
	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, current.Brigade.DepartmentID); err != nil {
		return nil, err
	}
	permissionCheckMs := time.Since(permissionStart).Milliseconds()

	readinessStart := time.Now()
	if err = b.checkStatusReadiness(ctx, log, start, current.Brigade, in.Status); err != nil {
		return nil, err
	}
	readinessCheckMs := time.Since(readinessStart).Milliseconds()

	if in.ChangedByUserID == nil {
		in.ChangedByUserID = in.ActorUserID
	}

	repoStart := time.Now()
	result, err := b.repo.SetBrigadeStatus(ctx, in)
	repoMs := time.Since(repoStart).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("service: SetBrigadeStatus error: %w", err)
	}

	log.Info("SetBrigadeStatus success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.String("status", string(in.Status)),
		zap.Int64("duration", time.Since(start).Milliseconds()),
		zap.Int64("validation_ms", validationMs),
		zap.Int64("get_brigade_ms", getBrigadeMs),
		zap.Int64("permission_check_ms", permissionCheckMs),
		zap.Int64("readiness_check_ms", readinessCheckMs),
		zap.Int64("repo_ms", repoMs),
		zap.String("target_status", string(in.Status)),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) GetBrigadeStatusHistory(ctx context.Context, in *models.GetBrigadeStatusHistoryInput) (*models.GetBrigadeStatusHistoryResult, error) {
	log := b.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("GetBrigadeStatusHistory")

	if err := in.Validate(); err != nil {
		log.Warn("GetBrigadeStatusHistory validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetBrigadeStatusHistory validation failed: %w: %v", models.ErrValidation, err)
	}

	current, err := b.repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{ID: in.BrigadeID})
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			log.Warn("GetBrigadeStatusHistory: Brigade not found",
				zap.String("brigade_id", in.BrigadeID.String()),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: GetBrigadeStatusHistory: get brigade: %w", err)
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, current.Brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := b.repo.GetBrigadeStatusHistory(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: GetBrigadeStatusHistory error: %w", err)
	}

	log.Info("GetBrigadeStatusHistory success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) GetAvailableBrigades(ctx context.Context, in *models.GetAvailableBrigadesInput) (*models.GetAvailableBrigadesResult, error) {
	log := b.log.With(pkg.RequestIDField(ctx))
	start := time.Now()
	validationStart := time.Now()

	log.Info("GetAvailableBrigades")

	if err := in.Validate(); err != nil {
		log.Warn("GetAvailableBrigades validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetAvailableBrigades validation failed: %w: %v", models.ErrValidation, err)
	}
	validationMs := time.Since(validationStart).Milliseconds()

	repoStart := time.Now()
	result, err := b.repo.GetAvailableBrigades(ctx, in)
	repoMs := time.Since(repoStart).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("service: GetAvailableBrigades error: %w", err)
	}

	log.Info("GetAvailableBrigades success",
		zap.String("department_id", in.DepartmentID.String()),
		zap.Int64("total", result.Total),
		zap.Int("required_roles_count", len(in.RequiredRoles)),
		zap.Int("required_skills_count", len(in.RequiredSkillIDs)),
		zap.Bool("has_location_filter", in.Longitude != nil && in.Latitude != nil),
		zap.Int64("duration", time.Since(start).Milliseconds()),
		zap.Int64("validation_ms", validationMs),
		zap.Int64("repo_ms", repoMs),
	)

	return result, nil
}

func (b *BrigadeServiceStruct) CheckBrigadeCanHandleTicket(ctx context.Context, in *models.CheckBrigadeCanHandleTicketInput) (*models.CheckBrigadeCanHandleTicketResult, error) {
	log := b.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("CheckBrigadeCanHandleTicket")

	if err := in.Validate(); err != nil {
		log.Warn("CheckBrigadeCanHandleTicket validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CheckBrigadeCanHandleTicket validation failed: %w: %v", models.ErrValidation, err)
	}

	result, err := b.repo.CheckBrigadeCanHandleTicket(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: CheckBrigadeCanHandleTicket error: %w", err)
	}

	log.Info("CheckBrigadeCanHandleTicket success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Bool("can_handle", result.CanHandle),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func checkPermissionAndDepartmentForAdminAndDispatcher(log *zap.Logger, start time.Time, actorRoles []string, actorDepartmentID *uuid.UUID, departmentID uuid.UUID) error {
	if actorRoles == nil {
		log.Warn("actor_roles is nil",
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
		log.Warn("actor_role is not admin or dispatcher",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return err
	}

	if actorDepartmentID == nil {
		err := models.ErrPermissionDenied
		log.Warn("actor_department is nil",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return err
	}

	if *actorDepartmentID != departmentID {
		err := models.ErrPermissionDenied
		log.Warn("actor_department is not match",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return err
	}

	return nil

}

func (b *BrigadeServiceStruct) checkStatusReadiness(ctx context.Context, log *zap.Logger, start time.Time, brigade *models.Brigade, targetStatus models.BrigadeStatus) error {
	switch targetStatus {
	case models.BrigadeStatusActive:
		reasons, err := b.repo.CheckBrigadeReadiness(ctx, brigade.ID, false, nil)
		if err != nil {
			return fmt.Errorf("service: check active readiness: %w", err)
		}
		if len(reasons) > 0 {
			err = models.ErrBrigadeUnavailable
			log.Warn("SetBrigadeStatus failed: brigade cannot become active",
				zap.String("brigade_id", brigade.ID.String()),
				zap.Strings("reasons", reasons),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.String("target_status", string(targetStatus)),
				zap.Error(err),
			)
			return err
		}
	case models.BrigadeStatusAvailable:
		if brigade.Status == models.BrigadeStatusInactive || brigade.Status == models.BrigadeStatusArchived {
			err := models.ErrBrigadeUnavailable
			log.Warn("SetBrigadeStatus failed: inactive or archived brigade cannot become available",
				zap.String("brigade_id", brigade.ID.String()),
				zap.String("current_status", string(brigade.Status)),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.String("target_status", string(targetStatus)),
				zap.Error(err),
			)
			return err
		}

		reasons, err := b.repo.CheckBrigadeReadiness(ctx, brigade.ID, true, nil)
		if err != nil {
			return fmt.Errorf("service: check available readiness: %w", err)
		}
		if len(reasons) > 0 {
			err = models.ErrBrigadeUnavailable
			log.Warn("SetBrigadeStatus failed: brigade cannot become available",
				zap.String("brigade_id", brigade.ID.String()),
				zap.Strings("reasons", reasons),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.String("target_status", string(targetStatus)),
				zap.Error(err),
			)
			return err
		}
	}

	return nil
}
