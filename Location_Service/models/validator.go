package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	DefaultLimit = int32(100)
	MaxLimit     = int32(1000)
)

func validatePoint(latitude, longitude float64) error {
	if latitude < -90 || latitude > 90 {
		return fmt.Errorf("latitude must be between -90 and 90")
	}
	if longitude < -180 || longitude > 180 {
		return fmt.Errorf("longitude must be between -180 and 180")
	}
	return nil
}

func validatePage(limit, offset int32) error {
	if limit < 0 || limit > MaxLimit {
		return fmt.Errorf("limit must be between 0 and %d", MaxLimit)
	}
	if offset < 0 {
		return fmt.Errorf("offset must not be negative")
	}
	return nil
}

func (in *RecordPositionInput) Validate() error {
	if in == nil {
		return fmt.Errorf("input is required")
	}
	if in.EventID == uuid.Nil {
		return fmt.Errorf("event_id is required")
	}
	if in.EventVersion != 1 {
		return fmt.Errorf("unsupported event_version: %d", in.EventVersion)
	}
	if strings.TrimSpace(in.DeviceID) == "" {
		return fmt.Errorf("device_id is required")
	}
	if in.VehicleID == uuid.Nil || in.BrigadeID == uuid.Nil {
		return fmt.Errorf("vehicle_id and brigade_id are required")
	}
	if in.Sequence == 0 {
		return fmt.Errorf("sequence must be positive")
	}
	if in.Sequence > uint64(1<<63-1) {
		return fmt.Errorf("sequence exceeds PostgreSQL BIGINT range")
	}
	if in.OccurredAt.IsZero() {
		return fmt.Errorf("occurred_at is required")
	}
	if err := validatePoint(in.Latitude, in.Longitude); err != nil {
		return err
	}
	if in.SpeedKMH < 0 || in.Heading < 0 || in.Heading >= 360 || in.AccuracyMeters < 0 {
		return fmt.Errorf("invalid movement measurements")
	}
	return nil
}

func (in *GetCurrentLocationInput) Validate() error {
	if in == nil || strings.TrimSpace(in.SubjectID) == "" {
		return fmt.Errorf("subject is required")
	}
	switch in.SubjectType {
	case SubjectTypeBrigade, SubjectTypeVehicle, SubjectTypeDevice:
		return nil
	}
	return fmt.Errorf("invalid subject_type")
}

func (in *GetCurrentLocationsInput) Validate() error {
	if in == nil || len(in.BrigadeIDs) == 0 {
		return fmt.Errorf("brigade_ids are required")
	}
	for _, id := range in.BrigadeIDs {
		if id == uuid.Nil {
			return fmt.Errorf("brigade_id is required")
		}
	}
	return nil
}

func (in *ListPositionHistoryInput) Validate() error {
	if in == nil || in.BrigadeID == uuid.Nil {
		return fmt.Errorf("brigade_id is required")
	}
	if in.From.IsZero() || in.To.IsZero() || !in.From.Before(in.To) {
		return fmt.Errorf("valid from/to interval is required")
	}
	if in.Order != "" && in.Order != SortOrderAsc && in.Order != SortOrderDesc {
		return fmt.Errorf("invalid order")
	}
	return validatePage(in.Limit, in.Offset)
}

func (in *FindNearbyBrigadesInput) Validate() error {
	if in == nil {
		return fmt.Errorf("input is required")
	}
	if err := validatePoint(in.Latitude, in.Longitude); err != nil {
		return err
	}
	if in.RadiusMeters <= 0 {
		return fmt.Errorf("radius_meters must be positive")
	}
	if in.Limit < 0 || in.Limit > MaxLimit {
		return fmt.Errorf("invalid limit")
	}
	return nil
}

func (in *CreateGeoZoneInput) Validate() error {
	if in == nil || in.DepartmentID == uuid.Nil || strings.TrimSpace(in.Name) == "" ||
		strings.TrimSpace(in.GeoJSON) == "" {
		return fmt.Errorf("department_id, name and geo_json are required")
	}
	return nil
}

func (in *UpdateGeoZoneInput) Validate() error {
	if in == nil || in.ID == uuid.Nil {
		return fmt.Errorf("id is required")
	}
	if in.Name == nil && in.GeoJSON == nil && in.Active == nil {
		return fmt.Errorf("at least one field must be provided")
	}
	return nil
}

func (in *DeleteGeoZoneInput) Validate() error {
	if in == nil || in.ID == uuid.Nil {
		return fmt.Errorf("id is required")
	}
	return nil
}
func (in *ListGeoZonesInput) Validate() error {
	if in == nil {
		return fmt.Errorf("input is required")
	}
	return validatePage(in.Limit, in.Offset)
}
func (in *CheckPointInZonesInput) Validate() error {
	if in == nil {
		return fmt.Errorf("input is required")
	}
	return validatePoint(in.Latitude, in.Longitude)
}
func (in *DetectLostSignalsInput) Validate() error {
	if in == nil || in.StaleBefore.IsZero() || in.OfflineBefore.IsZero() {
		return fmt.Errorf("thresholds are required")
	}
	if !in.OfflineBefore.Before(in.StaleBefore) {
		return fmt.Errorf("offline_before must be earlier than stale_before")
	}
	if in.StaleBefore.After(time.Now().Add(time.Minute)) {
		return fmt.Errorf("thresholds must not be in the future")
	}
	return validatePage(in.Limit, 0)
}
