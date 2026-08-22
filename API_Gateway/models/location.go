package models

type Position struct {
	ID             string   `json:"id"`
	EventID        string   `json:"event_id"`
	DeviceID       string   `json:"device_id"`
	VehicleID      string   `json:"vehicle_id"`
	BrigadeID      string   `json:"brigade_id"`
	Sequence       uint64   `json:"sequence"`
	Latitude       float64  `json:"latitude"`
	Longitude      float64  `json:"longitude"`
	SpeedKMH       float64  `json:"speed_kmh"`
	Heading        float64  `json:"heading"`
	AccuracyMeters float64  `json:"accuracy_meters"`
	AltitudeMeters *float64 `json:"altitude_meters,omitempty"`
	Simulated      bool     `json:"simulated"`
	RecordedAtUnix int64    `json:"recorded_at"`
	ReceivedAtUnix int64    `json:"received_at"`
}

type CurrentLocation struct {
	Position     *Position `json:"position"`
	SignalStatus string    `json:"signal_status"`
	StaleAfter   int64     `json:"stale_after"`
}

type GeoZone struct {
	ID            string `json:"id"`
	DepartmentID  string `json:"department_id"`
	Name          string `json:"name"`
	GeoJSON       string `json:"geo_json"`
	Active        bool   `json:"active"`
	CreatedAtUnix int64  `json:"created_at"`
	UpdatedAtUnix int64  `json:"updated_at"`
}

type NearbyBrigade struct {
	BrigadeID      string           `json:"brigade_id"`
	Location       *CurrentLocation `json:"location"`
	DistanceMeters float64          `json:"distance_meters"`
}

type RecordPositionRequest struct {
	EventID        string   `json:"event_id" binding:"required,uuid"`
	EventVersion   int32    `json:"event_version" binding:"required,eq=1"`
	OccurredAt     string   `json:"occurred_at" binding:"required"`
	DeviceID       string   `json:"device_id" binding:"required,max=128"`
	VehicleID      string   `json:"vehicle_id" binding:"required,uuid"`
	BrigadeID      string   `json:"brigade_id" binding:"required,uuid"`
	Sequence       uint64   `json:"sequence" binding:"required,min=1"`
	Latitude       float64  `json:"latitude" binding:"gte=-90,lte=90"`
	Longitude      float64  `json:"longitude" binding:"gte=-180,lte=180"`
	SpeedKMH       float64  `json:"speed_kmh" binding:"gte=0"`
	Heading        float64  `json:"heading" binding:"gte=0,lt=360"`
	AccuracyMeters float64  `json:"accuracy_meters" binding:"gte=0"`
	AltitudeMeters *float64 `json:"altitude_meters,omitempty"`
	Simulated      bool     `json:"simulated"`
}

type GetCurrentLocationRequest struct {
	SubjectType string `json:"subject_type" binding:"required,oneof=brigade vehicle device BRIGADE VEHICLE DEVICE"`
	SubjectID   string `json:"subject_id" binding:"required"`
}

type GetCurrentLocationsRequest struct {
	BrigadeIDs []string `json:"brigade_ids" binding:"required,min=1,dive,uuid"`
	AllowStale bool     `json:"allow_stale"`
}

type ListPositionHistoryRequest struct {
	BrigadeID string `json:"brigade_id" binding:"required,uuid"`
	From      string `json:"from" binding:"required"`
	To        string `json:"to" binding:"required"`
	Limit     int32  `json:"limit,omitempty" binding:"omitempty,min=1,max=1000"`
	Offset    int32  `json:"offset,omitempty" binding:"omitempty,min=0"`
	Order     string `json:"order,omitempty" binding:"omitempty,oneof=asc desc ASC DESC"`
}

type FindNearbyBrigadesRequest struct {
	Latitude               float64  `json:"latitude" binding:"gte=-90,lte=90"`
	Longitude              float64  `json:"longitude" binding:"gte=-180,lte=180"`
	RadiusMeters           float64  `json:"radius_meters" binding:"required,gt=0"`
	BrigadeIDs             []string `json:"brigade_ids,omitempty" binding:"omitempty,dive,uuid"`
	OnlyFresh              bool     `json:"only_fresh"`
	FreshnessWindowSeconds int64    `json:"freshness_window_seconds,omitempty" binding:"omitempty,gte=0"`
	Limit                  int32    `json:"limit,omitempty" binding:"omitempty,min=1,max=1000"`
}

type CreateGeoZoneRequest struct {
	DepartmentID string `json:"department_id" binding:"required,uuid"`
	Name         string `json:"name" binding:"required,max=255"`
	GeoJSON      string `json:"geo_json" binding:"required"`
}

type UpdateGeoZoneRequest struct {
	ID      string  `json:"id" binding:"required,uuid"`
	Name    *string `json:"name,omitempty" binding:"omitempty,max=255"`
	GeoJSON *string `json:"geo_json,omitempty"`
	Active  *bool   `json:"active,omitempty"`
}

type DeleteGeoZoneRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

type ListGeoZonesRequest struct {
	DepartmentID *string `json:"department_id,omitempty" binding:"omitempty,uuid"`
	Active       *bool   `json:"active,omitempty"`
	Limit        int32   `json:"limit,omitempty" binding:"omitempty,min=1,max=1000"`
	Offset       int32   `json:"offset,omitempty" binding:"omitempty,min=0"`
}

type CheckPointInZonesRequest struct {
	Latitude     float64  `json:"latitude" binding:"gte=-90,lte=90"`
	Longitude    float64  `json:"longitude" binding:"gte=-180,lte=180"`
	DepartmentID *string  `json:"department_id,omitempty" binding:"omitempty,uuid"`
	ZoneIDs      []string `json:"zone_ids,omitempty" binding:"omitempty,dive,uuid"`
}
