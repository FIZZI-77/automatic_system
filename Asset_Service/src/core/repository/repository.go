package repository

import (
	"asset/models"
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type RiskFacts struct {
	InstallationYear, ServiceLifeYears                                                          *int32
	Criticality                                                                                 float64
	Incidents90, Incidents365, Repeat90, SLAIncidents90, DaysSinceRepair, DaysInspectionOverdue int
	LastCondition                                                                               *float64
}
type AssetRepository interface {
	Create(context.Context, models.CreateInput) (*models.Asset, error)
	Update(context.Context, models.UpdateInput) (*models.Asset, error)
	Get(context.Context, uuid.UUID) (*models.Asset, error)
	List(context.Context, models.Filter) ([]*models.Asset, int64, error)
	ChangeStatus(context.Context, uuid.UUID, models.Status, uuid.UUID, string) (*models.Asset, error)
	Nearby(context.Context, float64, float64, float64, *string, int32) ([]*models.Asset, error)
	RecordIncident(context.Context, models.Incident) (*models.Incident, error)
	CompleteRepair(context.Context, models.Repair) (*models.Repair, error)
	RecordInspection(context.Context, models.Inspection) (*models.Inspection, error)
	CreatePlan(context.Context, models.Plan) (*models.Plan, error)
	DuePlans(context.Context, *uuid.UUID, time.Time, int32, int32) ([]*models.Plan, int64, error)
	RiskFacts(context.Context, uuid.UUID, time.Time) (RiskFacts, error)
	SavePrediction(context.Context, models.Prediction) error
	GetPrediction(context.Context, uuid.UUID) (*models.Prediction, error)
	ListIDs(context.Context, *uuid.UUID) ([]uuid.UUID, error)
}
type Repository struct{ AssetRepository }

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{AssetRepository: NewAssetRepoStruct(db)}
}

func IsNotFound(e error) bool {
	return errors.Is(e, pgx.ErrNoRows)
}
