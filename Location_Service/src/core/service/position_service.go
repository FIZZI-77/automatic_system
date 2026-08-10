package service

import (
	"context"
	"fmt"

	"location/models"
	"location/pkg"
	"location/src/core/repository"

	"go.uber.org/zap"
)

type PositionHistorySink interface {
	Add(position *models.Position) error
}

type PositionServiceStruct struct {
	repo    *repository.Repository
	history PositionHistorySink
	log     *zap.Logger
}

func NewPositionServiceStruct(repo *repository.Repository) *PositionServiceStruct {
	return NewPositionServiceStructWithHistory(repo, nil)
}

func NewPositionServiceStructWithHistory(
	repo *repository.Repository,
	history PositionHistorySink,
) *PositionServiceStruct {
	return NewPositionServiceStructWithLogger(repo, history, zap.NewNop())
}

func NewPositionServiceStructWithLogger(
	repo *repository.Repository,
	history PositionHistorySink,
	logger *zap.Logger,
) *PositionServiceStruct {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &PositionServiceStruct{repo: repo, history: history, log: logger}
}

func (s *PositionServiceStruct) RecordPosition(
	ctx context.Context,
	in *models.RecordPositionInput,
) (*models.RecordPositionResult, error) {
	log := s.log.With(pkg.RequestIDField(ctx), zap.String("operation", "RecordPosition"))
	log.Debug("service operation started")
	if err := in.Validate(); err != nil {
		log.Warn("service validation failed", zap.Error(err))
		return nil, validationError("RecordPosition", err)
	}
	location, err := s.repo.SaveCurrentLocation(ctx, in)
	if err != nil {
		log.Error("service operation failed", zap.Error(err))
		return nil, fmt.Errorf("service: RecordPosition: %w", err)
	}
	result := &models.RecordPositionResult{
		Position:  location.Position,
		Duplicate: location.Duplicate,
	}
	if !location.Duplicate && s.history != nil {
		if historyErr := s.history.Add(location.Position); historyErr != nil {
			log.Warn("position history buffer rejected point", zap.Error(historyErr))
		}
	}
	log.Debug(
		"service operation completed",
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.Bool("duplicate", location.Duplicate),
	)
	return result, nil
}

func (s *PositionServiceStruct) GetCurrentLocation(
	ctx context.Context,
	in *models.GetCurrentLocationInput,
) (*models.GetCurrentLocationResult, error) {
	if err := in.Validate(); err != nil {
		return nil, validationError("GetCurrentLocation", err)
	}
	result, err := s.repo.GetCurrentLocation(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: GetCurrentLocation: %w", err)
	}
	return result, nil
}

func (s *PositionServiceStruct) GetCurrentLocations(
	ctx context.Context,
	in *models.GetCurrentLocationsInput,
) (*models.GetCurrentLocationsResult, error) {
	if err := in.Validate(); err != nil {
		return nil, validationError("GetCurrentLocations", err)
	}
	result, err := s.repo.GetCurrentLocations(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: GetCurrentLocations: %w", err)
	}
	return result, nil
}

func (s *PositionServiceStruct) ListPositionHistory(
	ctx context.Context,
	in *models.ListPositionHistoryInput,
) (*models.ListPositionHistoryResult, error) {
	if err := in.Validate(); err != nil {
		return nil, validationError("ListPositionHistory", err)
	}
	result, err := s.repo.ListPositionHistory(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ListPositionHistory: %w", err)
	}
	return result, nil
}

func (s *PositionServiceStruct) FindNearbyBrigades(
	ctx context.Context,
	in *models.FindNearbyBrigadesInput,
) (*models.FindNearbyBrigadesResult, error) {
	if err := in.Validate(); err != nil {
		return nil, validationError("FindNearbyBrigades", err)
	}
	result, err := s.repo.FindNearbyBrigades(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: FindNearbyBrigades: %w", err)
	}
	return result, nil
}

func (s *PositionServiceStruct) DetectLostSignals(
	ctx context.Context,
	in *models.DetectLostSignalsInput,
) (*models.DetectLostSignalsResult, error) {
	log := s.log.With(pkg.RequestIDField(ctx), zap.String("operation", "DetectLostSignals"))
	if err := in.Validate(); err != nil {
		return nil, validationError("DetectLostSignals", err)
	}
	result, err := s.repo.DetectLostSignals(ctx, in)
	if err != nil {
		log.Error("detect lost signals failed", zap.Error(err))
		return nil, fmt.Errorf("service: DetectLostSignals: %w", err)
	}
	if len(result.Changes) > 0 {
		log.Info("signal statuses changed", zap.Int("changes", len(result.Changes)))
	}
	return result, nil
}

func validationError(operation string, err error) error {
	return fmt.Errorf("service: %s: %w: %v", operation, models.ErrValidation, err)
}
