package service

import (
	"context"
	"fmt"
	"strings"

	"location/models"
	"location/pkg"
	"location/src/core/repository"

	"go.uber.org/zap"
)

type GeoZoneServiceStruct struct {
	repo *repository.Repository
	log  *zap.Logger
}

func NewGeoZoneServiceStruct(repo *repository.Repository) *GeoZoneServiceStruct {
	return NewGeoZoneServiceStructWithLogger(repo, zap.NewNop())
}

func NewGeoZoneServiceStructWithLogger(
	repo *repository.Repository,
	logger *zap.Logger,
) *GeoZoneServiceStruct {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &GeoZoneServiceStruct{repo: repo, log: logger}
}

func (s *GeoZoneServiceStruct) CreateGeoZone(
	ctx context.Context,
	in *models.CreateGeoZoneInput,
) (*models.CreateGeoZoneResult, error) {
	log := s.log.With(pkg.RequestIDField(ctx), zap.String("operation", "CreateGeoZone"))
	if err := in.Validate(); err != nil {
		return nil, validationError("CreateGeoZone", err)
	}
	if !canManageZones(in.ActorRoles) {
		log.Warn("permission denied")
		return nil, models.ErrPermissionDenied
	}
	result, err := s.repo.CreateGeoZone(ctx, in)
	if err != nil {
		log.Error("create geo zone failed", zap.Error(err))
		return nil, fmt.Errorf("service: CreateGeoZone: %w", err)
	}
	log.Info("geo zone created", zap.String("zone_id", result.Zone.ID.String()))
	return result, nil
}

func (s *GeoZoneServiceStruct) UpdateGeoZone(
	ctx context.Context,
	in *models.UpdateGeoZoneInput,
) (*models.UpdateGeoZoneResult, error) {
	if err := in.Validate(); err != nil {
		return nil, validationError("UpdateGeoZone", err)
	}
	if !canManageZones(in.ActorRoles) {
		return nil, models.ErrPermissionDenied
	}
	result, err := s.repo.UpdateGeoZone(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: UpdateGeoZone: %w", err)
	}
	return result, nil
}

func (s *GeoZoneServiceStruct) DeleteGeoZone(
	ctx context.Context,
	in *models.DeleteGeoZoneInput,
) (*models.DeleteGeoZoneResult, error) {
	if err := in.Validate(); err != nil {
		return nil, validationError("DeleteGeoZone", err)
	}
	if !canManageZones(in.ActorRoles) {
		return nil, models.ErrPermissionDenied
	}
	result, err := s.repo.DeleteGeoZone(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: DeleteGeoZone: %w", err)
	}
	return result, nil
}

func (s *GeoZoneServiceStruct) ListGeoZones(
	ctx context.Context,
	in *models.ListGeoZonesInput,
) (*models.ListGeoZonesResult, error) {
	if err := in.Validate(); err != nil {
		return nil, validationError("ListGeoZones", err)
	}
	result, err := s.repo.ListGeoZones(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ListGeoZones: %w", err)
	}
	return result, nil
}

func (s *GeoZoneServiceStruct) CheckPointInZones(
	ctx context.Context,
	in *models.CheckPointInZonesInput,
) (*models.CheckPointInZonesResult, error) {
	if err := in.Validate(); err != nil {
		return nil, validationError("CheckPointInZones", err)
	}
	result, err := s.repo.CheckPointInZones(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: CheckPointInZones: %w", err)
	}
	return result, nil
}

func canManageZones(roles []string) bool {
	for _, role := range roles {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "admin", "system_admin", "dispatcher":
			return true
		}
	}
	return false
}
