package models

import (
	"time"

	"github.com/google/uuid"
)

// SubjectType задаёт тип доменной модели.
type SubjectType string

const (
	SubjectTypeBrigade SubjectType = "BRIGADE"
	SubjectTypeVehicle SubjectType = "VEHICLE"
	SubjectTypeDevice  SubjectType = "DEVICE"
)

// SignalStatus задаёт допустимое состояние модели.
type SignalStatus string

const (
	SignalStatusOnline  SignalStatus = "ONLINE"
	SignalStatusStale   SignalStatus = "STALE"
	SignalStatusOffline SignalStatus = "OFFLINE"
)

// SortOrder задаёт направление сортировки результатов.
type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
)

// Position описывает географическую позицию объекта в заданный момент.
type Position struct {
	ID             uuid.UUID `json:"id"`
	EventID        uuid.UUID `json:"event_id"`
	DeviceID       string    `json:"device_id"`
	VehicleID      uuid.UUID `json:"vehicle_id"`
	BrigadeID      uuid.UUID `json:"brigade_id"`
	Sequence       uint64    `json:"sequence"`
	Latitude       float64   `json:"latitude"`
	Longitude      float64   `json:"longitude"`
	SpeedKMH       float64   `json:"speed_kmh"`
	Heading        float64   `json:"heading"`
	AccuracyMeters float64   `json:"accuracy_meters"`
	AltitudeMeters *float64  `json:"altitude_meters,omitempty"`
	Simulated      bool      `json:"simulated"`
	RecordedAt     time.Time `json:"recorded_at"`
	ReceivedAt     time.Time `json:"received_at"`
}

// CurrentLocation описывает последнюю известную позицию объекта.
type CurrentLocation struct {
	Position     *Position    `json:"position"`
	SignalStatus SignalStatus `json:"signal_status"`
	StaleAfter   time.Time    `json:"stale_after"`
	Duplicate    bool         `json:"-"`
}

// GeoZone описывает географическую зону обслуживания.
type GeoZone struct {
	ID           uuid.UUID `json:"id"`
	DepartmentID uuid.UUID `json:"department_id"`
	Name         string    `json:"name"`
	GeoJSON      string    `json:"geo_json"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RecordPositionInput задаёт входные данные операции.
type RecordPositionInput struct {
	EventID        uuid.UUID
	EventVersion   int32
	OccurredAt     time.Time
	DeviceID       string
	VehicleID      uuid.UUID
	BrigadeID      uuid.UUID
	Sequence       uint64
	Latitude       float64
	Longitude      float64
	SpeedKMH       float64
	Heading        float64
	AccuracyMeters float64
	AltitudeMeters *float64
	Simulated      bool
}

// RecordPositionResult содержит результат операции.
type RecordPositionResult struct {
	Position  *Position
	Duplicate bool
}

// GetCurrentLocationInput задаёт входные данные операции.
type GetCurrentLocationInput struct {
	SubjectType SubjectType
	SubjectID   string
}

// GetCurrentLocationResult содержит результат операции.
type GetCurrentLocationResult struct{ Location *CurrentLocation }

// GetCurrentLocationsInput задаёт входные данные операции.
type GetCurrentLocationsInput struct {
	BrigadeIDs []uuid.UUID
	AllowStale bool
}

// GetCurrentLocationsResult содержит результат операции.
type GetCurrentLocationsResult struct {
	Locations map[uuid.UUID]*CurrentLocation
	Missing   []uuid.UUID
}

// ListPositionHistoryInput задаёт входные данные операции.
type ListPositionHistoryInput struct {
	BrigadeID uuid.UUID
	From      time.Time
	To        time.Time
	Limit     int32
	Offset    int32
	Order     SortOrder
}

// ListPositionHistoryResult содержит результат операции.
type ListPositionHistoryResult struct {
	Positions []*Position
	Total     int64
}

// FindNearbyBrigadesInput задаёт входные данные операции.
type FindNearbyBrigadesInput struct {
	Latitude        float64
	Longitude       float64
	RadiusMeters    float64
	BrigadeIDs      []uuid.UUID
	OnlyFresh       bool
	FreshnessWindow time.Duration
	Limit           int32
}

// NearbyBrigade описывает доменную модель.
type NearbyBrigade struct {
	BrigadeID      uuid.UUID
	Location       *CurrentLocation
	DistanceMeters float64
}

// FindNearbyBrigadesResult содержит результат операции.
type FindNearbyBrigadesResult struct{ Brigades []*NearbyBrigade }

// CreateGeoZoneInput задаёт входные данные операции.
type CreateGeoZoneInput struct {
	DepartmentID uuid.UUID
	Name         string
	GeoJSON      string
	ActorRoles   []string
}

// CreateGeoZoneResult содержит результат операции.
type CreateGeoZoneResult struct{ Zone *GeoZone }

// UpdateGeoZoneInput задаёт входные данные операции.
type UpdateGeoZoneInput struct {
	ID         uuid.UUID
	Name       *string
	GeoJSON    *string
	Active     *bool
	ActorRoles []string
}

// UpdateGeoZoneResult содержит результат операции.
type UpdateGeoZoneResult struct{ Zone *GeoZone }

// DeleteGeoZoneInput задаёт входные данные операции.
type DeleteGeoZoneInput struct {
	ID         uuid.UUID
	ActorRoles []string
}

// DeleteGeoZoneResult содержит результат операции.
type DeleteGeoZoneResult struct{ Zone *GeoZone }

// ListGeoZonesInput задаёт входные данные операции.
type ListGeoZonesInput struct {
	DepartmentID *uuid.UUID
	Active       *bool
	Limit        int32
	Offset       int32
}

// ListGeoZonesResult содержит результат операции.
type ListGeoZonesResult struct {
	Zones []*GeoZone
	Total int64
}

// CheckPointInZonesInput задаёт входные данные операции.
type CheckPointInZonesInput struct {
	Latitude     float64
	Longitude    float64
	DepartmentID *uuid.UUID
	ZoneIDs      []uuid.UUID
}

// CheckPointInZonesResult содержит результат операции.
type CheckPointInZonesResult struct{ Zones []*GeoZone }

// DetectLostSignalsInput задаёт входные данные операции.
type DetectLostSignalsInput struct {
	StaleBefore   time.Time
	OfflineBefore time.Time
	Limit         int32
}

// SignalChange описывает доменную модель.
type SignalChange struct {
	BrigadeID uuid.UUID
	From      SignalStatus
	To        SignalStatus
	ChangedAt time.Time
}

// DetectLostSignalsResult содержит результат операции.
type DetectLostSignalsResult struct{ Changes []*SignalChange }
