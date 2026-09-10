package models

import (
	"time"

	"github.com/google/uuid"
)

type SubjectType string

const (
	SubjectTypeBrigade SubjectType = "BRIGADE"
	SubjectTypeVehicle SubjectType = "VEHICLE"
	SubjectTypeDevice  SubjectType = "DEVICE"
)

type SignalStatus string

const (
	SignalStatusOnline  SignalStatus = "ONLINE"
	SignalStatusStale   SignalStatus = "STALE"
	SignalStatusOffline SignalStatus = "OFFLINE"
)

type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
)

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

type CurrentLocation struct {
	Position     *Position    `json:"position"`
	SignalStatus SignalStatus `json:"signal_status"`
	StaleAfter   time.Time    `json:"stale_after"`
	Duplicate    bool         `json:"-"`
}

type GeoZone struct {
	ID           uuid.UUID `json:"id"`
	DepartmentID uuid.UUID `json:"department_id"`
	Name         string    `json:"name"`
	GeoJSON      string    `json:"geo_json"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

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

type RecordPositionResult struct {
	Position  *Position
	Duplicate bool
}

type GetCurrentLocationInput struct {
	SubjectType SubjectType
	SubjectID   string
}

type GetCurrentLocationResult struct{ Location *CurrentLocation }

type GetCurrentLocationsInput struct {
	BrigadeIDs []uuid.UUID
	AllowStale bool
}

type GetCurrentLocationsResult struct {
	Locations map[uuid.UUID]*CurrentLocation
	Missing   []uuid.UUID
}

type ListPositionHistoryInput struct {
	BrigadeID uuid.UUID
	From      time.Time
	To        time.Time
	Limit     int32
	Offset    int32
	Order     SortOrder
}

type ListPositionHistoryResult struct {
	Positions []*Position
	Total     int64
}

type FindNearbyBrigadesInput struct {
	Latitude        float64
	Longitude       float64
	RadiusMeters    float64
	BrigadeIDs      []uuid.UUID
	OnlyFresh       bool
	FreshnessWindow time.Duration
	Limit           int32
}

type NearbyBrigade struct {
	BrigadeID      uuid.UUID
	Location       *CurrentLocation
	DistanceMeters float64
}

type FindNearbyBrigadesResult struct{ Brigades []*NearbyBrigade }

type CreateGeoZoneInput struct {
	DepartmentID uuid.UUID
	Name         string
	GeoJSON      string
	ActorRoles   []string
}
type CreateGeoZoneResult struct{ Zone *GeoZone }

type UpdateGeoZoneInput struct {
	ID         uuid.UUID
	Name       *string
	GeoJSON    *string
	Active     *bool
	ActorRoles []string
}
type UpdateGeoZoneResult struct{ Zone *GeoZone }

type DeleteGeoZoneInput struct {
	ID         uuid.UUID
	ActorRoles []string
}
type DeleteGeoZoneResult struct{ Zone *GeoZone }

type ListGeoZonesInput struct {
	DepartmentID *uuid.UUID
	Active       *bool
	Limit        int32
	Offset       int32
}
type ListGeoZonesResult struct {
	Zones []*GeoZone
	Total int64
}

type CheckPointInZonesInput struct {
	Latitude     float64
	Longitude    float64
	DepartmentID *uuid.UUID
	ZoneIDs      []uuid.UUID
}
type CheckPointInZonesResult struct{ Zones []*GeoZone }

type DetectLostSignalsInput struct {
	StaleBefore   time.Time
	OfflineBefore time.Time
	Limit         int32
}
type SignalChange struct {
	BrigadeID uuid.UUID
	From      SignalStatus
	To        SignalStatus
	ChangedAt time.Time
}
type DetectLostSignalsResult struct{ Changes []*SignalChange }
