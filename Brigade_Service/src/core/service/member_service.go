package service

import (
	"brigade/models"
	"brigade/pkg"
	"brigade/src/core/repository"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type MemberServiceStruct struct {
	repo *repository.Repo
	log  *zap.Logger
}

func NewMemberServiceStruct(repo *repository.Repo, log *zap.Logger) *MemberServiceStruct {
	return &MemberServiceStruct{
		repo: repo,
		log:  log,
	}
}

func (m *MemberServiceStruct) AddBrigadeMember(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error) {
	log := m.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("AddBrigadeMember")

	if err := in.Validate(); err != nil {
		log.Warn("AddBrigadeMember validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: AddBrigadeMember validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := m.getBrigadeForMemberOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "AddBrigadeMember")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	// TODO: validate user/profile through Profile Service when it is implemented.
	existing, err := m.repo.GetBrigadeByUserID(ctx, &models.GetBrigadeByUserIDInput{
		UserID:     in.UserID,
		OnlyActive: true,
	})
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		return nil, fmt.Errorf("service: AddBrigadeMember: check active membership: %w", err)
	}
	if existing != nil && existing.Member != nil {
		err = models.ErrAlreadyExists
		log.Warn("AddBrigadeMember failed: user already has active brigade",
			zap.String("user_id", in.UserID.String()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, err
	}

	if in.ChangedByUserID == nil {
		in.ChangedByUserID = in.ActorUserID
	}

	result, err := m.repo.AddBrigadeMember(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: AddBrigadeMember: %w", err)
	}

	log.Info("AddBrigadeMember success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.String("user_id", in.UserID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (m *MemberServiceStruct) RemoveBrigadeMember(ctx context.Context, in *models.RemoveBrigadeMemberInput) (*models.RemoveBrigadeMemberResult, error) {
	log := m.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("RemoveBrigadeMember")

	if err := in.Validate(); err != nil {
		log.Warn("RemoveBrigadeMember validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: RemoveBrigadeMember validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := m.getBrigadeForMemberOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "RemoveBrigadeMember")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	if in.ChangedByUserID == nil {
		in.ChangedByUserID = in.ActorUserID
	}

	if err = m.checkCanRemoveMember(ctx, log, start, brigade, in); err != nil {
		return nil, err
	}

	result, err := m.repo.RemoveBrigadeMember(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: RemoveBrigadeMember: %w", err)
	}

	log.Info("RemoveBrigadeMember success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.String("member_id", in.MemberID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (m *MemberServiceStruct) ChangeBrigadeMemberRole(ctx context.Context, in *models.ChangeBrigadeMemberRoleInput) (*models.ChangeBrigadeMemberRoleResult, error) {
	log := m.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("ChangeBrigadeMemberRole")

	if err := in.Validate(); err != nil {
		log.Warn("ChangeBrigadeMemberRole validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ChangeBrigadeMemberRole validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := m.getBrigadeForMemberOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "ChangeBrigadeMemberRole")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	if in.ChangedByUserID == nil {
		in.ChangedByUserID = in.ActorUserID
	}

	result, err := m.repo.ChangeBrigadeMemberRole(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ChangeBrigadeMemberRole: %w", err)
	}

	log.Info("ChangeBrigadeMemberRole success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.String("member_id", in.MemberID.String()),
		zap.String("role", string(in.Role)),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (m *MemberServiceStruct) SetBrigadeMemberAvailability(ctx context.Context, in *models.SetBrigadeMemberAvailabilityInput) (*models.SetBrigadeMemberAvailabilityResult, error) {
	log := m.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("SetBrigadeMemberAvailability")

	if err := in.Validate(); err != nil {
		log.Warn("SetBrigadeMemberAvailability validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: SetBrigadeMemberAvailability validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := m.getBrigadeForMemberOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "SetBrigadeMemberAvailability")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	if in.ChangedByUserID == nil {
		in.ChangedByUserID = in.ActorUserID
	}

	result, err := m.repo.SetBrigadeMemberAvailability(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: SetBrigadeMemberAvailability: %w", err)
	}

	log.Info("SetBrigadeMemberAvailability success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.String("member_id", in.MemberID.String()),
		zap.String("status", string(in.Status)),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (m *MemberServiceStruct) ListBrigadeMembers(ctx context.Context, in *models.ListBrigadeMembersInput) (*models.ListBrigadeMembersResult, error) {
	log := m.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("ListBrigadeMembers")

	if err := in.Validate(); err != nil {
		log.Warn("ListBrigadeMembers validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListBrigadeMembers validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := m.getBrigadeForMemberOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "ListBrigadeMembers")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := m.repo.ListBrigadeMembers(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ListBrigadeMembers: %w", err)
	}

	log.Info("ListBrigadeMembers success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (m *MemberServiceStruct) GetBrigadeMemberHistory(ctx context.Context, in *models.GetBrigadeMemberHistoryInput) (*models.GetBrigadeMemberHistoryResult, error) {
	log := m.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("GetBrigadeMemberHistory")

	if err := in.Validate(); err != nil {
		log.Warn("GetBrigadeMemberHistory validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetBrigadeMemberHistory validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := m.getBrigadeForMemberOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "GetBrigadeMemberHistory")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := m.repo.GetBrigadeMemberHistory(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: GetBrigadeMemberHistory: %w", err)
	}

	log.Info("GetBrigadeMemberHistory success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (m *MemberServiceStruct) GetBrigadeMemberStatusHistory(ctx context.Context, in *models.GetBrigadeMemberStatusHistoryInput) (*models.GetBrigadeMemberStatusHistoryResult, error) {
	log := m.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("GetBrigadeMemberStatusHistory")

	if err := in.Validate(); err != nil {
		log.Warn("GetBrigadeMemberStatusHistory validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetBrigadeMemberStatusHistory validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := m.getBrigadeForMemberOperation(ctx, log, start, in.BrigadeID, in.ActorUserID, in.ActorDepartmentID, in.ActorRoles, "GetBrigadeMemberStatusHistory")
	if err != nil {
		return nil, err
	}

	if err = checkPermissionAndDepartmentForAdminAndDispatcher(log, start, in.ActorRoles, in.ActorDepartmentID, brigade.DepartmentID); err != nil {
		return nil, err
	}

	result, err := m.repo.GetBrigadeMemberStatusHistory(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: GetBrigadeMemberStatusHistory: %w", err)
	}

	log.Info("GetBrigadeMemberStatusHistory success",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (m *MemberServiceStruct) GetBrigadeByUserID(ctx context.Context, in *models.GetBrigadeByUserIDInput) (*models.GetBrigadeByUserIDResult, error) {
	log := m.log.With(pkg.RequestIDField(ctx))
	start := time.Now()

	log.Info("GetBrigadeByUserID")

	if err := in.Validate(); err != nil {
		log.Warn("GetBrigadeByUserID validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetBrigadeByUserID validation failed: %w: %v", models.ErrValidation, err)
	}

	result, err := m.repo.GetBrigadeByUserID(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: GetBrigadeByUserID: %w", err)
	}

	log.Info("GetBrigadeByUserID success",
		zap.String("user_id", in.UserID.String()),
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (m *MemberServiceStruct) getBrigadeForMemberOperation(
	ctx context.Context,
	log *zap.Logger,
	start time.Time,
	brigadeID uuid.UUID,
	actorUserID *uuid.UUID,
	actorDepartmentID *uuid.UUID,
	actorRoles []string,
	operation string,
) (*models.Brigade, error) {
	input := &models.GetBrigadeByIDInput{
		ID:                brigadeID,
		ActorUserID:       actorUserID,
		ActorDepartmentID: actorDepartmentID,
		ActorRoles:        actorRoles,
	}

	brigade, err := m.repo.GetBrigadeByID(ctx, input)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			log.Warn(operation+" failed: brigade not found",
				zap.String("brigade_id", input.ID.String()),
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
			return nil, err
		}
		return nil, fmt.Errorf("service: %s: get brigade: %w", operation, err)
	}

	if brigade.Brigade.Status == models.BrigadeStatusArchived {
		err = models.ErrPermissionDenied
		log.Warn(operation+" failed: brigade archived",
			zap.String("brigade_id", input.ID.String()),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, err
	}

	return brigade.Brigade, nil
}

func (m *MemberServiceStruct) checkCanRemoveMember(ctx context.Context, log *zap.Logger, start time.Time, brigade *models.Brigade, in *models.RemoveBrigadeMemberInput) error {
	if !brigadeStatusRequiresActiveMember(brigade.Status) {
		return nil
	}

	active := true
	members, err := m.repo.ListBrigadeMembers(ctx, &models.ListBrigadeMembersInput{
		BrigadeID: in.BrigadeID,
		Active:    &active,
		Limit:     2,
		Offset:    0,
	})
	if err != nil {
		return fmt.Errorf("service: RemoveBrigadeMember: check active members: %w", err)
	}

	if len(members.Members) == 1 && members.Members[0].ID == in.MemberID {
		err = models.ErrBrigadeUnavailable
		log.Warn("RemoveBrigadeMember failed: cannot remove last active member from active brigade",
			zap.String("brigade_id", in.BrigadeID.String()),
			zap.String("member_id", in.MemberID.String()),
			zap.String("brigade_status", string(brigade.Status)),
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return err
	}

	return nil
}

func brigadeStatusRequiresActiveMember(status models.BrigadeStatus) bool {
	switch status {
	case models.BrigadeStatusActive,
		models.BrigadeStatusAvailable,
		models.BrigadeStatusBusy,
		models.BrigadeStatusOnRoute,
		models.BrigadeStatusOnSite,
		models.BrigadeStatusOffline:
		return true
	default:
		return false
	}
}
