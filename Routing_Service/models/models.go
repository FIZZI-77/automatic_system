package models

import "time"

// TravelMode задаёт режим выполнения операции.
type TravelMode string

const (
	TravelModeAuto       TravelMode = "auto"
	TravelModeTruck      TravelMode = "truck"
	TravelModeBicycle    TravelMode = "bicycle"
	TravelModePedestrian TravelMode = "pedestrian"
)

// RouteStatus задаёт допустимое состояние модели.
type RouteStatus string

const (
	RouteStatusPlanned   RouteStatus = "PLANNED"
	RouteStatusActive    RouteStatus = "ACTIVE"
	RouteStatusCompleted RouteStatus = "COMPLETED"
	RouteStatusCancelled RouteStatus = "CANCELLED"
)

// Point описывает доменную модель.
type Point struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// VehicleConstraints описывает доменную модель.
type VehicleConstraints struct {
	HeightMeters       *float64 `json:"height_meters,omitempty"`
	WidthMeters        *float64 `json:"width_meters,omitempty"`
	LengthMeters       *float64 `json:"length_meters,omitempty"`
	WeightTons         *float64 `json:"weight_tons,omitempty"`
	AxleLoadTons       *float64 `json:"axle_load_tons,omitempty"`
	HazardousMaterials bool     `json:"hazardous_materials"`
}

// RouteOptions описывает доменную модель.
type RouteOptions struct {
	TravelMode   TravelMode          `json:"travel_mode"`
	DepartureAt  *time.Time          `json:"departure_at,omitempty"`
	Alternatives bool                `json:"alternatives"`
	Vehicle      *VehicleConstraints `json:"vehicle,omitempty"`
}

// RouteSummary описывает доменную модель.
type RouteSummary struct {
	DistanceMeters  float64 `json:"distance_meters"`
	DurationSeconds int64   `json:"duration_seconds"`
}

// RouteLeg описывает доменную модель.
type RouteLeg struct {
	From            Point   `json:"from"`
	To              Point   `json:"to"`
	DistanceMeters  float64 `json:"distance_meters"`
	DurationSeconds int64   `json:"duration_seconds"`
}

// CalculatedRoute описывает доменную модель.
type CalculatedRoute struct {
	Summary         RouteSummary `json:"summary"`
	EncodedPolyline string       `json:"encoded_polyline"`
	Legs            []RouteLeg   `json:"legs"`
	SnappedPoints   []Point      `json:"snapped_points"`
	Engine          string       `json:"engine"`
}

// Route описывает сохранённый маршрут и состояние его расчёта.
type Route struct {
	ID                        string          `json:"id"`
	TicketID                  string          `json:"ticket_id"`
	BrigadeID                 string          `json:"brigade_id"`
	Status                    RouteStatus     `json:"status"`
	Origin                    Point           `json:"origin"`
	Destination               Point           `json:"destination"`
	Waypoints                 []Point         `json:"waypoints"`
	Options                   RouteOptions    `json:"options"`
	Calculation               CalculatedRoute `json:"calculation"`
	Revision                  int32           `json:"revision"`
	CreatedAt                 time.Time       `json:"created_at"`
	UpdatedAt                 time.Time       `json:"updated_at"`
	CalculationStartedAt      *time.Time      `json:"calculation_started_at,omitempty"`
	CalculationFinishedAt     *time.Time      `json:"calculation_finished_at,omitempty"`
	CalculationDurationMillis *float64        `json:"calculation_duration_ms,omitempty"`
	CalculationSuccess        *bool           `json:"calculation_success,omitempty"`
}

// CalculationFailure описывает доменную модель.
type CalculationFailure struct {
	AggregateType         string     `json:"aggregate_type"`
	AggregateID           string     `json:"aggregate_id"`
	TicketID              string     `json:"ticket_id"`
	BrigadeID             string     `json:"brigade_id"`
	RouteID               string     `json:"route_id,omitempty"`
	Engine                string     `json:"engine"`
	TravelMode            TravelMode `json:"travel_mode"`
	FailureCode           string     `json:"failure_code"`
	FailureReason         string     `json:"failure_reason"`
	CalculationStartedAt  time.Time  `json:"calculation_started_at"`
	CalculationFinishedAt time.Time  `json:"calculation_finished_at"`
	CalculationDurationMS float64    `json:"calculation_duration_ms"`
}

// BuildRouteInput задаёт входные данные операции.
type BuildRouteInput struct {
	Origin      Point
	Destination Point
	Waypoints   []Point
	Options     RouteOptions
}

// BuildMatrixInput задаёт входные данные операции.
type BuildMatrixInput struct {
	Sources []Point
	Targets []Point
	Options RouteOptions
}

// MatrixCell описывает доменную модель.
type MatrixCell struct {
	SourceIndex     int32
	TargetIndex     int32
	DistanceMeters  float64
	DurationSeconds int64
	Reachable       bool
}

// Candidate описывает доменную модель.
type Candidate struct {
	BrigadeID string
	Location  Point
}

// RankedCandidate описывает доменную модель.
type RankedCandidate struct {
	Candidate
	Rank           int32
	DistanceMeters float64
	ETASeconds     int64
	Reachable      bool
}

// RankCandidatesInput задаёт входные данные операции.
type RankCandidatesInput struct {
	Destination Point
	Candidates  []Candidate
	Options     RouteOptions
	Limit       int32
}

// CreateRouteInput задаёт входные данные операции.
type CreateRouteInput struct {
	TicketID    string
	BrigadeID   string
	Origin      Point
	Destination Point
	Waypoints   []Point
	Options     RouteOptions
}

// RecalculateRouteInput задаёт входные данные операции.
type RecalculateRouteInput struct {
	ID              string
	CurrentPosition Point
}

// ListRoutesInput задаёт входные данные операции.
type ListRoutesInput struct {
	AllowedTicketIDs []string
	TicketID         *string
	BrigadeID        *string
	Status           *RouteStatus
	Limit            int32
	Offset           int32
}

// ListRoutesResult содержит результат операции.
type ListRoutesResult struct {
	Routes []*Route
	Total  int64
}
