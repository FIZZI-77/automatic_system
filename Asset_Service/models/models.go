package models

import (
	"errors"
	"github.com/google/uuid"
	"time"
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
	ID                                                                                                                 uuid.UUID
	ExternalID                                                                                                         *string
	DepartmentID                                                                                                       uuid.UUID
	Type, Name, Address, District, Municipality, Geometry, Model, SerialNumber, Owner, ServiceOrganization, Contractor string
	Status                                                                                                             Status
	InstallationYear, ServiceLifeYears                                                                                 *int32
	WarrantyUntil                                                                                                      *time.Time
	InspectionIntervalDays, ResponseNormMinutes, RepairNormMinutes                                                     int32
	Criticality, RiskScore                                                                                             float64
	RiskLevel                                                                                                          RiskLevel
	LastRepairAt, NextInspectionAt                                                                                     *time.Time
	CreatedAt, UpdatedAt                                                                                               time.Time
}
type CreateInput struct {
	Asset
	ActorID uuid.UUID
}
type UpdateInput struct {
	ID                                  uuid.UUID
	Name, Address, Geometry, Contractor *string
	Criticality                         *float64
}
type Filter struct {
	DepartmentID   *uuid.UUID
	Type, District *string
	Status         *Status
	RiskLevel      *RiskLevel
	Limit, Offset  int32
}
type Prediction struct {
	AssetID            uuid.UUID
	Score, Probability float64
	Level              RiskLevel
	Factors            []string
	Action             string
	CalculatedAt       time.Time
}
type Incident struct {
	ID, AssetID                                uuid.UUID
	TicketID                                   *uuid.UUID
	FailureType, Description, Source, Priority string
	Repeated                                   bool
	OccurredAt                                 time.Time
}
type Repair struct {
	ID, AssetID                     uuid.UUID
	IncidentID, TicketID, BrigadeID *uuid.UUID
	Description, ReplacedComponents string
	DurationMinutes                 int32
	CompletedAt                     time.Time
}
type Inspection struct {
	ID, AssetID, InspectorID     uuid.UUID
	Kind, Result, Recommendation string
	DefectFound                  bool
	ConditionScore               float64
	InspectedAt                  time.Time
}
type Plan struct {
	ID, AssetID     uuid.UUID
	Kind            string
	IntervalDays    int32
	NextDueAt       time.Time
	Active          bool
	LastCompletedAt *time.Time
}
