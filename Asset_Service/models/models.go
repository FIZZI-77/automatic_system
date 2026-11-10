package models

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status задаёт допустимое состояние модели.
type Status string

// RiskLevel описывает доменную модель.
type RiskLevel string

const (
	StatusPlanned        Status    = "PLANNED"
	StatusActive         Status    = "ACTIVE"
	StatusDamaged        Status    = "DAMAGED"
	StatusRepair         Status    = "UNDER_REPAIR"
	StatusReplace        Status    = "NEEDS_REPLACEMENT"
	StatusDecommissioned Status    = "DECOMMISSIONED"
	RiskLow              RiskLevel = "LOW"
	RiskMedium           RiskLevel = "MEDIUM"
	RiskHigh             RiskLevel = "HIGH"
	RiskCritical         RiskLevel = "CRITICAL"
)

var ErrForbidden = errors.New("permission denied")

// Asset описывает объект инфраструктуры и его эксплуатационные характеристики.
type Asset struct {
	ID                     uuid.UUID
	ExternalID             *string
	DepartmentID           uuid.UUID
	Type                   string
	Name                   string
	Address                string
	District               string
	Municipality           string
	Geometry               string
	Model                  string
	SerialNumber           string
	Owner                  string
	ServiceOrganization    string
	Contractor             string
	Status                 Status
	InstallationYear       *int32
	ServiceLifeYears       *int32
	WarrantyUntil          *time.Time
	InspectionIntervalDays int32
	ResponseNormMinutes    int32
	RepairNormMinutes      int32
	Criticality            float64
	RiskScore              float64
	RiskLevel              RiskLevel
	LastRepairAt           *time.Time
	NextInspectionAt       *time.Time
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// CreateInput задаёт входные данные операции.
type CreateInput struct {
	Asset
	ActorID uuid.UUID
}

// UpdateInput задаёт входные данные операции.
type UpdateInput struct {
	ID          uuid.UUID
	Name        *string
	Address     *string
	Geometry    *string
	Contractor  *string
	Criticality *float64
}

// Filter задаёт условия фильтрации.
type Filter struct {
	DepartmentID *uuid.UUID
	Type         *string
	District     *string
	Status       *Status
	RiskLevel    *RiskLevel
	Limit        int32
	Offset       int32
}

// Prediction описывает доменную модель.
type Prediction struct {
	AssetID      uuid.UUID
	Score        float64
	Probability  float64
	Level        RiskLevel
	Factors      []string
	Action       string
	CalculatedAt time.Time
}

// Incident описывает доменную модель.
type Incident struct {
	ID          uuid.UUID
	AssetID     uuid.UUID
	TicketID    *uuid.UUID
	FailureType string
	Description string
	Source      string
	Priority    string
	Repeated    bool
	OccurredAt  time.Time
}

// Repair описывает доменную модель.
type Repair struct {
	ID                 uuid.UUID
	AssetID            uuid.UUID
	IncidentID         *uuid.UUID
	TicketID           *uuid.UUID
	BrigadeID          *uuid.UUID
	Description        string
	ReplacedComponents string
	DurationMinutes    int32
	CompletedAt        time.Time
}

// Inspection описывает доменную модель.
type Inspection struct {
	ID             uuid.UUID
	AssetID        uuid.UUID
	InspectorID    uuid.UUID
	Kind           string
	Result         string
	Recommendation string
	DefectFound    bool
	ConditionScore float64
	InspectedAt    time.Time
}

// Plan описывает доменную модель.
type Plan struct {
	ID              uuid.UUID
	AssetID         uuid.UUID
	Kind            string
	IntervalDays    int32
	NextDueAt       time.Time
	Active          bool
	LastCompletedAt *time.Time
}
