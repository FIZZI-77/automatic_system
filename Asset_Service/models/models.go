package models

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

type Status string
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
type CreateInput struct {
	Asset
	ActorID uuid.UUID
}
type UpdateInput struct {
	ID          uuid.UUID
	Name        *string
	Address     *string
	Geometry    *string
	Contractor  *string
	Criticality *float64
}
type Filter struct {
	DepartmentID *uuid.UUID
	Type         *string
	District     *string
	Status       *Status
	RiskLevel    *RiskLevel
	Limit        int32
	Offset       int32
}
type Prediction struct {
	AssetID      uuid.UUID
	Score        float64
	Probability  float64
	Level        RiskLevel
	Factors      []string
	Action       string
	CalculatedAt time.Time
}
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
type Plan struct {
	ID              uuid.UUID
	AssetID         uuid.UUID
	Kind            string
	IntervalDays    int32
	NextDueAt       time.Time
	Active          bool
	LastCompletedAt *time.Time
}
