package service

import (
	"asset/models"
	"asset/src/core/repository"
	"context"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"time"
)

type AssetService interface {
	Create(context.Context, models.CreateInput, bool) (*models.Asset, error)
	Update(context.Context, models.UpdateInput, bool) (*models.Asset, error)
	Get(context.Context, uuid.UUID) (*models.Asset, error)
	List(context.Context, models.Filter) ([]*models.Asset, int64, error)
	ChangeStatus(context.Context, uuid.UUID, models.Status, uuid.UUID, string, bool) (*models.Asset, error)
	Nearby(context.Context, float64, float64, float64, *string, int32) ([]*models.Asset, error)
	Incident(context.Context, models.Incident, bool) (*models.Incident, *models.Prediction, error)
	Repair(context.Context, models.Repair, bool) (*models.Repair, *models.Prediction, error)
	Inspection(context.Context, models.Inspection, bool) (*models.Inspection, *models.Prediction, error)
	CreatePlan(context.Context, models.Plan, bool) (*models.Plan, error)
	Due(context.Context, *uuid.UUID, time.Time, int32, int32) ([]*models.Plan, int64, error)
	Prediction(context.Context, uuid.UUID) (*models.Prediction, error)
	Recalculate(context.Context, *uuid.UUID, bool) (int64, error)
}
type Service struct{ AssetService }

func NewService(r repository.AssetRepository, l *zap.Logger) *Service {
	return &Service{
		AssetService: &AssetServiceStruct{
			repo: r,
			log:  l,
		},
	}
}
