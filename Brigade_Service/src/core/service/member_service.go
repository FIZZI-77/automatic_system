package service

import (
	"brigade/models"
	"brigade/pkg"
	"brigade/src/core/repository"
	"context"
	"errors"
	"fmt"
	"github.com/bytedance/gopkg/util/logger"
	"go.uber.org/zap"
	"time"
)

type MemberServiceStruct struct {
	repo   repository.Repo
	logger *zap.Logger
}

func NewMemberServiceStruct(repo repository.Repo, logger *zap.Logger) *MemberServiceStruct {
	return &MemberServiceStruct{
		repo:   repo,
		logger: logger,
	}
}

func (m *MemberServiceStruct) AddBrigadeMember(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error) {
	logger := m.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("Adding brigade member to brigade")

	if err := in.Validate(); err != nil {
		logger.Warn("AddBrigadeMember validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: AddBrigadeMember validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := m.isBrigadeExistAndNotArchive(ctx, &models.GetBrigadeByIDInput{
		ID:                in.BrigadeID,
		ActorUserID:       in.ActorUserID,
		ActorDepartmentID: in.ActorDepartmentID,
		ActorRoles:        in.ActorRoles,
	}, start)

	if err != nil {
		logger.Warn("RemoveBrigadeMember failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: RemoveBrigadeMember failed: %w", err)
	}

	//TODO сделать проверку валидности профиля

	err = checkPermissionAndDepartmentForAdminAndDispatcher(logger, start, in.ActorRoles, in.ActorDepartmentID, brigade.Brigade.DepartmentID)
	if err != nil {
		logger.Warn("service: AddBrigadeMember: AddBrigadeMember failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: AddBrigadeMember failed: %w", err)
	}

	isUserInBrigade, err := m.repo.GetBrigadeByUserID(ctx, &models.GetBrigadeByUserIDInput{
		UserID: in.UserID,
	})

	if err != nil && !errors.Is(err, models.ErrNotFound) {
		logger.Warn("service: AddBrigadeMember: GetBrigadeMember failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: AddBrigadeMember failed: %w", err)
	}

	if isUserInBrigade != nil {
		logger.Warn("service: AddBrigadeMember failed, user already in brigade",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(errors.New("user is already in brigade")),
		)
		return nil, fmt.Errorf("service: AddBrigadeMember failed, user is already in brigade: %w", err)
	}

	result, err := m.repo.AddBrigadeMember(ctx, in)
	if err != nil {
		logger.Warn("service: AddBrigadeMember: AddBrigadeMember failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: AddBrigadeMember failed: %w", err)
	}

	logger.Info("Adding brigade member to brigade",
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (m *MemberServiceStruct) RemoveBrigadeMember(ctx context.Context, in *models.RemoveBrigadeMemberInput) (*models.RemoveBrigadeMemberResult, error) {
	logger := m.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("start RemoveBrigadeMember")

	if err := in.Validate(); err != nil {
		logger.Warn("RemoveBrigadeMember validation failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: RemoveBrigadeMember validation failed: %w: %v", models.ErrValidation, err)
	}

	brigade, err := m.isBrigadeExistAndNotArchive(ctx, &models.GetBrigadeByIDInput{
		ID:                in.BrigadeID,
		ActorUserID:       in.ActorUserID,
		ActorDepartmentID: in.ActorDepartmentID,
		ActorRoles:        in.ActorRoles,
	}, start)

	if err != nil {
		logger.Warn("RemoveBrigadeMember failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: RemoveBrigadeMember failed: %w", err)
	}

	err = checkPermissionAndDepartmentForAdminAndDispatcher(logger, start, in.ActorRoles, in.ActorDepartmentID, brigade.Brigade.DepartmentID)
	if err != nil {
		logger.Warn("RemoveBrigadeMember failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: RemoveBrigadeMember failed: %w", err)
	}

	isUserInBrigade, err := m.repo.GetBrigadeByUserID(ctx, &models.GetBrigadeByUserIDInput{
		UserID: in.MemberID,
	})

	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			logger.Warn("RemoveBrigadeMember failed, brigade not found",
				zap.Int64("duration", time.Since(start).Milliseconds()),
				zap.Error(err),
			)
		}
		logger.Warn("service: RemoveBrigadeMember: GetBrigadeMember failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: RemoveBrigadeMember failed: %w", err)
	}

	if isUserInBrigade.Brigade.ID != in.BrigadeID {
		logger.Warn("RemoveBrigadeMember failed, member in another brigade",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(errors.New("member in another brigade")),
		)
		return nil, fmt.Errorf("service: RemoveBrigadeMember failed, member in another brigade: %w", err)
	}

	result, err := m.repo.RemoveBrigadeMember(ctx, in)
	if err != nil {
		logger.Warn("RemoveBrigadeMember failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: RemoveBrigadeMember failed: %w", err)
	}

	logger.Info("Removed brigade member from brigade",
		zap.Int64("duration", time.Since(start).Milliseconds()),
	)

	return result, nil
}

func (m *MemberServiceStruct) ChangeBrigadeMemberRole(ctx context.Context, in *models.ChangeBrigadeMemberRoleInput) (*models.ChangeBrigadeMemberRoleResult, error) {

}

func (m *MemberServiceStruct) SetBrigadeMemberAvailability(ctx context.Context, in *models.SetBrigadeMemberAvailabilityInput) (*models.SetBrigadeMemberAvailabilityResult, error) {

}

func (m *MemberServiceStruct) ListBrigadeMembers(ctx context.Context, in *models.ListBrigadeMembersInput) (*models.ListBrigadeMembersResult, error) {

}

func (m *MemberServiceStruct) GetBrigadeMemberHistory(ctx context.Context, in *models.GetBrigadeMemberHistoryInput) (*models.GetBrigadeMemberHistoryResult, error) {

}

func (m *MemberServiceStruct) GetBrigadeMemberStatusHistory(ctx context.Context, in *models.GetBrigadeMemberStatusHistoryInput) (*models.GetBrigadeMemberStatusHistoryResult, error) {

}

func (m *MemberServiceStruct) GetBrigadeByUserID(ctx context.Context, in *models.GetBrigadeByUserIDInput) (*models.GetBrigadeByUserIDResult, error) {

}

func (m *MemberServiceStruct) isBrigadeExistAndNotArchive(ctx context.Context, in *models.GetBrigadeByIDInput, start time.Time) (*models.GetBrigadeByIDResult, error) {
	brigade, err := m.repo.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{
		ID:                in.ID,
		ActorUserID:       in.ActorUserID,
		ActorDepartmentID: in.ActorDepartmentID,
		ActorRoles:        in.ActorRoles,
	})

	if err != nil {
		logger.Warn("RemoveBrigadeMember failed",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: RemoveBrigadeMember failed: %w", err)
	}

	if brigade == nil {
		logger.Warn("RemoveBrigadeMember failed, brigade not found",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(errors.New("RemoveBrigadeMember failed, brigade not found")),
		)
		return nil, fmt.Errorf("service: RemoveBrigadeMember failed, brigade not found: %w", err)
	}

	if brigade.Brigade.Status == models.BrigadeStatusArchived {
		logger.Warn("Brigade already archived",
			zap.Int64("duration", time.Since(start).Milliseconds()),
			zap.Error(errors.New("brigade already archived")),
		)
		return nil, fmt.Errorf("brigade already archived: %w", err)
	}
	return brigade, nil
}
