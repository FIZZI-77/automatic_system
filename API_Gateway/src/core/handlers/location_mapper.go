package handlers

import (
	"strings"

	"gateway/models"

	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
)

// toProtoSubjectType преобразует тип бригады, машины или устройства без учёта
// регистра; неизвестное значение даёт UNSPECIFIED.
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

// toProtoLocationSortOrder преобразует asc или desc без учёта регистра;
// неизвестное значение даёт UNSPECIFIED.
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

// fromProtoSignalStatus преобразует состояние сигнала в строку HTTP-модели;
// неизвестное значение даёт пустую строку.
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

// fromProtoPosition преобразует телеметрию в HTTP-модель с датами в Unix-секундах,
// сохраняя необязательную высоту; nil сохраняет как nil.
func fromProtoPosition(value *locationv1.Position) *models.Position {

	if value == nil {
		return nil
	}

	return &models.Position{
		ID:             value.GetId(),
		EventID:        value.GetEventId(),
		DeviceID:       value.GetDeviceId(),
		VehicleID:      value.GetVehicleId(),
		BrigadeID:      value.GetBrigadeId(),
		Sequence:       value.GetSequence(),
		Latitude:       value.GetLatitude(),
		Longitude:      value.GetLongitude(),
		SpeedKMH:       value.GetSpeedKmh(),
		Heading:        value.GetHeading(),
		AccuracyMeters: value.GetAccuracyMeters(),
		AltitudeMeters: value.AltitudeMeters,
		Simulated:      value.GetSimulated(),
		RecordedAtUnix: timestampUnix(value.GetRecordedAt()),
		ReceivedAtUnix: timestampUnix(value.GetReceivedAt()),
	}
}

// fromProtoCurrentLocation преобразует позицию, состояние сигнала и срок
// актуальности в HTTP-модель; nil сохраняет как nil.
func fromProtoCurrentLocation(value *locationv1.CurrentLocation) *models.CurrentLocation {

	if value == nil {
		return nil
	}

	return &models.CurrentLocation{
		Position:     fromProtoPosition(value.GetPosition()),
		SignalStatus: fromProtoSignalStatus(value.GetSignalStatus()),
		StaleAfter:   timestampUnix(value.GetStaleAfter()),
	}
}

// fromProtoGeoZone преобразует зону с GeoJSON, активностью и датами
// в HTTP-модель; nil сохраняет как nil.
func fromProtoGeoZone(value *locationv1.GeoZone) *models.GeoZone {

	if value == nil {
		return nil
	}

	return &models.GeoZone{
		ID:            value.GetId(),
		DepartmentID:  value.GetDepartmentId(),
		Name:          value.GetName(),
		GeoJSON:       value.GetGeoJson(),
		Active:        value.GetActive(),
		CreatedAtUnix: timestampUnix(value.GetCreatedAt()),
		UpdatedAtUnix: timestampUnix(value.GetUpdatedAt()),
	}
}

// fromProtoGeoZones преобразует зоны с сохранением порядка и nil-элементов;
// пустой вход даёт пустой ненулевой срез.
func fromProtoGeoZones(values []*locationv1.GeoZone) []*models.GeoZone {
	result := make([]*models.GeoZone, 0, len(values))
	for _, value := range values {
		result = append(result, fromProtoGeoZone(value))
	}
	return result
}
