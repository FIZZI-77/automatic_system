package models

import "time"

type AssetIDRequest struct {
	AssetID string `json:"asset_id" binding:"required,uuid"`
}
type CreateAssetRequest struct {
	ExternalID             *string `json:"external_id,omitempty"`
	DepartmentID           string  `json:"department_id" binding:"required,uuid"`
	Type                   string  `json:"type" binding:"required"`
	Name                   string  `json:"name" binding:"required"`
	Address                string  `json:"address,omitempty"`
	District               string  `json:"district,omitempty"`
	Municipality           string  `json:"municipality,omitempty"`
	GeometryGeoJSON        string  `json:"geometry_geo_json" binding:"required"`
	Model                  string  `json:"model,omitempty"`
	SerialNumber           string  `json:"serial_number,omitempty"`
	InstallationYear       *int32  `json:"installation_year,omitempty"`
	ServiceLifeYears       *int32  `json:"service_life_years,omitempty"`
	Owner                  string  `json:"owner,omitempty"`
	ServiceOrganization    string  `json:"service_organization,omitempty"`
	Contractor             string  `json:"contractor,omitempty"`
	InspectionIntervalDays int32   `json:"inspection_interval_days,omitempty"`
	ResponseNormMinutes    int32   `json:"response_norm_minutes,omitempty"`
	RepairNormMinutes      int32   `json:"repair_norm_minutes,omitempty"`
	Criticality            float64 `json:"criticality" binding:"min=0,max=1"`
}
type UpdateAssetRequest struct {
	AssetID         string   `json:"asset_id" binding:"required,uuid"`
	Name            *string  `json:"name,omitempty"`
	Address         *string  `json:"address,omitempty"`
	GeometryGeoJSON *string  `json:"geometry_geo_json,omitempty"`
	Contractor      *string  `json:"contractor,omitempty"`
	Criticality     *float64 `json:"criticality,omitempty" binding:"omitempty,min=0,max=1"`
}
type ChangeAssetStatusRequest struct {
	AssetID string `json:"asset_id" binding:"required,uuid"`
	Status  string `json:"status" binding:"required"`
	Reason  string `json:"reason,omitempty"`
}
type ListAssetsRequest struct {
	DepartmentID *string `json:"department_id,omitempty"`
	Type         *string `json:"type,omitempty"`
	District     *string `json:"district,omitempty"`
	Status       *string `json:"status,omitempty"`
	RiskLevel    *string `json:"risk_level,omitempty"`
	Limit        int32   `json:"limit,omitempty"`
	Offset       int32   `json:"offset,omitempty"`
}
type NearbyAssetsRequest struct {
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	RadiusMeters float64 `json:"radius_meters" binding:"required,gt=0"`
	Type         *string `json:"type,omitempty"`
	Limit        int32   `json:"limit,omitempty"`
}
type AssetIncidentRequest struct {
	AssetID     string     `json:"asset_id" binding:"required,uuid"`
	TicketID    *string    `json:"ticket_id,omitempty"`
	FailureType string     `json:"failure_type,omitempty"`
	Description string     `json:"description,omitempty"`
	Source      string     `json:"source,omitempty"`
	Priority    string     `json:"priority,omitempty"`
	OccurredAt  *time.Time `json:"occurred_at,omitempty"`
}
type AssetRepairRequest struct {
	AssetID            string     `json:"asset_id" binding:"required,uuid"`
	IncidentID         *string    `json:"incident_id,omitempty"`
	TicketID           *string    `json:"ticket_id,omitempty"`
	BrigadeID          *string    `json:"brigade_id,omitempty"`
	Description        string     `json:"description,omitempty"`
	ReplacedComponents string     `json:"replaced_components,omitempty"`
	DurationMinutes    int32      `json:"duration_minutes"`
	CompletedAt        *time.Time `json:"completed_at,omitempty"`
}
type AssetInspectionRequest struct {
	AssetID        string     `json:"asset_id" binding:"required,uuid"`
	Kind           string     `json:"kind,omitempty"`
	Result         string     `json:"result,omitempty"`
	Recommendation string     `json:"recommendation,omitempty"`
	DefectFound    bool       `json:"defect_found"`
	ConditionScore float64    `json:"condition_score" binding:"min=0,max=1"`
	InspectedAt    *time.Time `json:"inspected_at,omitempty"`
}
type MaintenancePlanRequest struct {
	AssetID      string    `json:"asset_id" binding:"required,uuid"`
	Kind         string    `json:"kind" binding:"required"`
	IntervalDays int32     `json:"interval_days" binding:"required,gt=0"`
	NextDueAt    time.Time `json:"next_due_at" binding:"required"`
}
type DueMaintenanceRequest struct {
	DepartmentID *string   `json:"department_id,omitempty" binding:"omitempty,uuid"`
	DueBefore    time.Time `json:"due_before" binding:"required"`
	Limit        int32     `json:"limit,omitempty"`
	Offset       int32     `json:"offset,omitempty"`
}
type RecalculateAssetRisksRequest struct {
	DepartmentID *string `json:"department_id,omitempty" binding:"omitempty,uuid"`
}
