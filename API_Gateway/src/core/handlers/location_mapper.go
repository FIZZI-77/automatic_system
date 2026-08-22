package handlers

import (
	"strings"

	"gateway/models"

	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
)

func toProtoSubjectType(value string) locationv1.SubjectType {
	switch strings.ToUpper(value) {
	case "BRIGADE":
		return locationv1.SubjectType_SUBJECT_TYPE_BRIGADE
	case "VEHICLE":
		return locationv1.SubjectType_SUBJECT_TYPE_VEHICLE
	case "DEVICE":
		return locationv1.SubjectType_SUBJECT_TYPE_DEVICE
	default:
		return locationv1.SubjectType_SUBJECT_TYPE_UNSPECIFIED
	}
}

func toProtoLocationSortOrder(value string) locationv1.SortOrder {
	switch strings.ToLower(value) {
	case "asc":
		return locationv1.SortOrder_SORT_ORDER_ASC
	case "desc":
		return locationv1.SortOrder_SORT_ORDER_DESC
	default:
		return locationv1.SortOrder_SORT_ORDER_UNSPECIFIED
	}
}

func fromProtoSignalStatus(value locationv1.SignalStatus) string {
	switch value {
	case locationv1.SignalStatus_SIGNAL_STATUS_ONLINE:
		return "ONLINE"
	case locationv1.SignalStatus_SIGNAL_STATUS_STALE:
		return "STALE"
	case locationv1.SignalStatus_SIGNAL_STATUS_OFFLINE:
		return "OFFLINE"
	default:
		return ""
	}
}

func fromProtoPosition(value *locationv1.Position) *models.Position {
	if value == nil {
		return nil
	}
	return &models.Position{ID: value.GetId(), EventID: value.GetEventId(), DeviceID: value.GetDeviceId(), VehicleID: value.GetVehicleId(), BrigadeID: value.GetBrigadeId(), Sequence: value.GetSequence(), Latitude: value.GetLatitude(), Longitude: value.GetLongitude(), SpeedKMH: value.GetSpeedKmh(), Heading: value.GetHeading(), AccuracyMeters: value.GetAccuracyMeters(), AltitudeMeters: value.AltitudeMeters, Simulated: value.GetSimulated(), RecordedAtUnix: timestampUnix(value.GetRecordedAt()), ReceivedAtUnix: timestampUnix(value.GetReceivedAt())}
}

func fromProtoCurrentLocation(value *locationv1.CurrentLocation) *models.CurrentLocation {
	if value == nil {
		return nil
	}
	return &models.CurrentLocation{Position: fromProtoPosition(value.GetPosition()), SignalStatus: fromProtoSignalStatus(value.GetSignalStatus()), StaleAfter: timestampUnix(value.GetStaleAfter())}
}

func fromProtoGeoZone(value *locationv1.GeoZone) *models.GeoZone {
	if value == nil {
		return nil
	}
	return &models.GeoZone{ID: value.GetId(), DepartmentID: value.GetDepartmentId(), Name: value.GetName(), GeoJSON: value.GetGeoJson(), Active: value.GetActive(), CreatedAtUnix: timestampUnix(value.GetCreatedAt()), UpdatedAtUnix: timestampUnix(value.GetUpdatedAt())}
}

func fromProtoGeoZones(values []*locationv1.GeoZone) []*models.GeoZone {
	result := make([]*models.GeoZone, 0, len(values))
	for _, value := range values {
		result = append(result, fromProtoGeoZone(value))
	}
	return result
}
