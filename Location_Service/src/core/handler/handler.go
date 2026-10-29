package handler

import (
	"context"
	"errors"
	"strings"
	"time"

	"location/models"
	"location/src/core/service"

	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Handler struct {
	locationv1.UnimplementedLocationServiceServer
	service *service.Service
}

// New создаёт gRPC-обработчик координат и геозон с переданным сервисом.
func New(service *service.Service) *Handler { return &Handler{service: service} }

// RecordPosition проверяет UUID события, машины и бригады и обязательное время,
// затем передаёт телеметрию сервису. Возвращает позицию и признак дубликата;
// ошибки формата даёт как InvalidArgument, остальные преобразует через toStatus.
func (h *Handler) RecordPosition(
	ctx context.Context,
	req *locationv1.RecordPositionRequest,
) (*locationv1.RecordPositionResponse, error) {
	eventID, err := parseUUID(req.GetEventId(), "event_id")

	if err != nil {
		return nil, err
	}

	vehicleID, err := parseUUID(req.GetVehicleId(), "vehicle_id")

	if err != nil {
		return nil, err
	}

	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")

	if err != nil {
		return nil, err
	}

	occurredAt, err := requiredTime(req.GetOccurredAt(), "occurred_at")

	if err != nil {
		return nil, err
	}

	result, callErr := h.service.RecordPosition(
		ctx,
		&models.RecordPositionInput{
			EventID:        eventID,
			EventVersion:   req.GetEventVersion(),
			OccurredAt:     occurredAt,
			DeviceID:       req.GetDeviceId(),
			VehicleID:      vehicleID,
			BrigadeID:      brigadeID,
			Sequence:       req.GetSequence(),
			Latitude:       req.GetLatitude(),
			Longitude:      req.GetLongitude(),
			SpeedKMH:       req.GetSpeedKmh(),
			Heading:        req.GetHeading(),
			AccuracyMeters: req.GetAccuracyMeters(),
			AltitudeMeters: req.AltitudeMeters,
			Simulated:      req.GetSimulated(),
		},
	)

	if callErr != nil {
		return nil, toStatus(callErr)
	}

	return &locationv1.RecordPositionResponse{
		Position:  positionToProto(result.Position),
		Duplicate: result.Duplicate,
	}, nil
}

// GetCurrentLocation преобразует тип субъекта и передаёт его строковый ID сервису;
// возвращает текущую позицию, состояние сигнала и срок актуальности в protobuf.
func (h *Handler) GetCurrentLocation(
	ctx context.Context,
	req *locationv1.GetCurrentLocationRequest,
) (*locationv1.GetCurrentLocationResponse, error) {
	result, err := h.service.GetCurrentLocation(
		ctx,
		&models.GetCurrentLocationInput{
			SubjectType: subjectTypeFromProto(req.GetSubjectType()),
			SubjectID:   req.GetSubjectId(),
		},
	)

	if err != nil {
		return nil, toStatus(err)
	}

	return &locationv1.GetCurrentLocationResponse{
		Location: currentLocationToProto(result.Location),
	}, nil
}

// GetCurrentLocations разбирает UUID бригад и передаёт AllowStale сервису;
// возвращает карту позиций по строковым UUID и список отсутствующих бригад.
func (h *Handler) GetCurrentLocations(
	ctx context.Context,
	req *locationv1.GetCurrentLocationsRequest,
) (*locationv1.GetCurrentLocationsResponse, error) {
	ids, err := parseUUIDs(req.GetBrigadeIds(), "brigade_ids")

	if err != nil {
		return nil, err
	}

	result, callErr := h.service.GetCurrentLocations(
		ctx,
		&models.GetCurrentLocationsInput{BrigadeIDs: ids, AllowStale: req.GetAllowStale()},
	)

	if callErr != nil {
		return nil, toStatus(callErr)
	}

	response := &locationv1.GetCurrentLocationsResponse{
		Locations:         make(map[string]*locationv1.CurrentLocation, len(result.Locations)),
		MissingBrigadeIds: uuidStrings(result.Missing),
	}
	for id, location := range result.Locations {
		response.Locations[id.String()] = currentLocationToProto(location)
	}
	return response, nil
}

// ListPositionHistory проверяет UUID бригады и обе обязательные временные границы,
// передаёт пагинацию и порядок сервису и возвращает историю с общим счётчиком.
func (h *Handler) ListPositionHistory(
	ctx context.Context,
	req *locationv1.ListPositionHistoryRequest,
) (*locationv1.ListPositionHistoryResponse, error) {
	brigadeID, err := parseUUID(req.GetBrigadeId(), "brigade_id")

	if err != nil {
		return nil, err
	}

	from, err := requiredTime(req.GetFrom(), "from")

	if err != nil {
		return nil, err
	}

	to, err := requiredTime(req.GetTo(), "to")

	if err != nil {
		return nil, err
	}

	result, callErr := h.service.ListPositionHistory(
		ctx,
		&models.ListPositionHistoryInput{
			BrigadeID: brigadeID,
			From:      from,
			To:        to,
			Limit:     req.GetLimit(),
			Offset:    req.GetOffset(),
			Order:     sortOrderFromProto(req.GetOrder()),
		},
	)

	if callErr != nil {
		return nil, toStatus(callErr)
	}

	response := &locationv1.ListPositionHistoryResponse{
		Positions: make([]*locationv1.Position, 0, len(result.Positions)),
		Total:     result.Total,
	}
	for _, position := range result.Positions {
		response.Positions = append(response.Positions, positionToProto(position))
	}
	return response, nil
}

// FindNearbyBrigades разбирает UUID бригад и передаёт координаты, радиус, лимит
// и условия свежести сервису. Окно свежести переводит из секунд в Duration;
// возвращает бригады с позициями и расстояниями в метрах.
func (h *Handler) FindNearbyBrigades(
	ctx context.Context,
	req *locationv1.FindNearbyBrigadesRequest,
) (*locationv1.FindNearbyBrigadesResponse, error) {
	ids, err := parseUUIDs(req.GetBrigadeIds(), "brigade_ids")

	if err != nil {
		return nil, err
	}

	result, callErr := h.service.FindNearbyBrigades(
		ctx,
		&models.FindNearbyBrigadesInput{
			Latitude:        req.GetLatitude(),
			Longitude:       req.GetLongitude(),
			RadiusMeters:    req.GetRadiusMeters(),
			BrigadeIDs:      ids,
			OnlyFresh:       req.GetOnlyFresh(),
			FreshnessWindow: time.Duration(req.GetFreshnessWindowSeconds()) * time.Second,
			Limit:           req.GetLimit(),
		},
	)

	if callErr != nil {
		return nil, toStatus(callErr)
	}

	response := &locationv1.FindNearbyBrigadesResponse{
		Brigades: make([]*locationv1.NearbyBrigade, 0, len(result.Brigades)),
	}
	for _, item := range result.Brigades {
		response.Brigades = append(
			response.Brigades,
			&locationv1.NearbyBrigade{
				BrigadeId:      item.BrigadeID.String(),
				Location:       currentLocationToProto(item.Location),
				DistanceMeters: item.DistanceMeters,
			},
		)
	}
	return response, nil
}

// CreateGeoZone разбирает UUID ведомства и передаёт имя, GeoJSON и роли из
// метаданных сервису; проверка доступа выполняется сервисным слоем.
func (h *Handler) CreateGeoZone(
	ctx context.Context,
	req *locationv1.CreateGeoZoneRequest,
) (*locationv1.CreateGeoZoneResponse, error) {
	departmentID, err := parseUUID(req.GetDepartmentId(), "department_id")

	if err != nil {
		return nil, err
	}

	result, callErr := h.service.CreateGeoZone(
		ctx,
		&models.CreateGeoZoneInput{
			DepartmentID: departmentID,
			Name:         req.GetName(),
			GeoJSON:      req.GetGeoJson(),
			ActorRoles:   actorRoles(ctx),
		},
	)

	if callErr != nil {
		return nil, toStatus(callErr)
	}

	return &locationv1.CreateGeoZoneResponse{Zone: zoneToProto(result.Zone)}, nil
}

// UpdateGeoZone разбирает UUID зоны и передаёт сервису только заданные поля
// имени, геометрии и активности вместе с ролями из входящих метаданных.
func (h *Handler) UpdateGeoZone(
	ctx context.Context,
	req *locationv1.UpdateGeoZoneRequest,
) (*locationv1.UpdateGeoZoneResponse, error) {
	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		return nil, err
	}

	result, callErr := h.service.UpdateGeoZone(
		ctx,
		&models.UpdateGeoZoneInput{
			ID:         id,
			Name:       req.Name,
			GeoJSON:    req.GeoJson,
			Active:     req.Active,
			ActorRoles: actorRoles(ctx),
		},
	)

	if callErr != nil {
		return nil, toStatus(callErr)
	}

	return &locationv1.UpdateGeoZoneResponse{Zone: zoneToProto(result.Zone)}, nil
}

// DeleteGeoZone разбирает UUID зоны и передаёт удаление с ролями из метаданных
// сервису; возвращает зону из результата и преобразует доменные ошибки в gRPC.
func (h *Handler) DeleteGeoZone(
	ctx context.Context,
	req *locationv1.DeleteGeoZoneRequest,
) (*locationv1.DeleteGeoZoneResponse, error) {
	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		return nil, err
	}

	result, callErr := h.service.DeleteGeoZone(
		ctx,
		&models.DeleteGeoZoneInput{ID: id, ActorRoles: actorRoles(ctx)},
	)

	if callErr != nil {
		return nil, toStatus(callErr)
	}

	return &locationv1.DeleteGeoZoneResponse{Zone: zoneToProto(result.Zone)}, nil
}

// ListGeoZones разбирает необязательный UUID ведомства и возвращает страницу
// зон с общим счётчиком, сохраняя фильтр активности и параметры пагинации.
func (h *Handler) ListGeoZones(
	ctx context.Context,
	req *locationv1.ListGeoZonesRequest,
) (*locationv1.ListGeoZonesResponse, error) {
	var departmentID *uuid.UUID

	if req.DepartmentId != nil {
		id, err := parseUUID(req.GetDepartmentId(), "department_id")

		if err != nil {
			return nil, err
		}

		departmentID = &id
	}

	result, callErr := h.service.ListGeoZones(
		ctx,
		&models.ListGeoZonesInput{
			DepartmentID: departmentID,
			Active:       req.Active,
			Limit:        req.GetLimit(),
			Offset:       req.GetOffset(),
		},
	)

	if callErr != nil {
		return nil, toStatus(callErr)
	}

	response := &locationv1.ListGeoZonesResponse{
		Zones: make([]*locationv1.GeoZone, 0, len(result.Zones)),
		Total: result.Total,
	}
	for _, zone := range result.Zones {
		response.Zones = append(response.Zones, zoneToProto(zone))
	}
	return response, nil
}

// CheckPointInZones разбирает UUID зон и необязательного ведомства, передаёт
// координаты сервису и возвращает совпавшие зоны в protobuf.
func (h *Handler) CheckPointInZones(
	ctx context.Context,
	req *locationv1.CheckPointInZonesRequest,
) (*locationv1.CheckPointInZonesResponse, error) {
	var departmentID *uuid.UUID

	if req.DepartmentId != nil {
		id, err := parseUUID(req.GetDepartmentId(), "department_id")

		if err != nil {
			return nil, err
		}

		departmentID = &id
	}

	ids, err := parseUUIDs(req.GetZoneIds(), "zone_ids")

	if err != nil {
		return nil, err
	}

	result, callErr := h.service.CheckPointInZones(
		ctx,
		&models.CheckPointInZonesInput{
			Latitude:     req.GetLatitude(),
			Longitude:    req.GetLongitude(),
			DepartmentID: departmentID,
			ZoneIDs:      ids,
		},
	)

	if callErr != nil {
		return nil, toStatus(callErr)
	}

	response := &locationv1.CheckPointInZonesResponse{
		Zones: make([]*locationv1.GeoZone, 0, len(result.Zones)),
	}
	for _, zone := range result.Zones {
		response.Zones = append(response.Zones, zoneToProto(zone))
	}
	return response, nil
}

// positionToProto преобразует позицию с телеметрией, UUID, датами и необязательной
// высотой в protobuf; nil сохраняет как nil.
func positionToProto(position *models.Position) *locationv1.Position {

	if position == nil {
		return nil
	}

	result := &locationv1.Position{
		Id:             position.ID.String(),
		EventId:        position.EventID.String(),
		DeviceId:       position.DeviceID,
		VehicleId:      position.VehicleID.String(),
		BrigadeId:      position.BrigadeID.String(),
		Sequence:       position.Sequence,
		Latitude:       position.Latitude,
		Longitude:      position.Longitude,
		SpeedKmh:       position.SpeedKMH,
		Heading:        position.Heading,
		AccuracyMeters: position.AccuracyMeters,
		Simulated:      position.Simulated,
		RecordedAt:     timestamppb.New(position.RecordedAt),
		ReceivedAt:     timestamppb.New(position.ReceivedAt),
	}
	result.AltitudeMeters = position.AltitudeMeters
	return result
}

// currentLocationToProto преобразует позицию, состояние сигнала и срок актуальности
// в protobuf; nil сохраняет как nil.
func currentLocationToProto(location *models.CurrentLocation) *locationv1.CurrentLocation {

	if location == nil {
		return nil
	}

	return &locationv1.CurrentLocation{
		Position:     positionToProto(location.Position),
		SignalStatus: signalStatusToProto(location.SignalStatus),
		StaleAfter:   timestamppb.New(location.StaleAfter),
	}
}

// zoneToProto преобразует зону с GeoJSON, ведомством, активностью и датами
// в protobuf; для nil возвращает nil.
func zoneToProto(zone *models.GeoZone) *locationv1.GeoZone {

	if zone == nil {
		return nil
	}

	return &locationv1.GeoZone{
		Id:           zone.ID.String(),
		DepartmentId: zone.DepartmentID.String(),
		Name:         zone.Name,
		GeoJson:      zone.GeoJSON,
		Active:       zone.Active,
		CreatedAt:    timestamppb.New(zone.CreatedAt),
		UpdatedAt:    timestamppb.New(zone.UpdatedAt),
	}
}

// signalStatusToProto преобразует состояние сигнала в enum;
// неизвестное состояние даёт UNSPECIFIED.
func signalStatusToProto(value models.SignalStatus) locationv1.SignalStatus {
	switch value {
	case models.SignalStatusOnline:
		return locationv1.SignalStatus_SIGNAL_STATUS_ONLINE
	case models.SignalStatusStale:
		return locationv1.SignalStatus_SIGNAL_STATUS_STALE
	case models.SignalStatusOffline:
		return locationv1.SignalStatus_SIGNAL_STATUS_OFFLINE
	}
	return locationv1.SignalStatus_SIGNAL_STATUS_UNSPECIFIED
}

// subjectTypeFromProto преобразует тип бригады, машины или устройства;
// неизвестное значение возвращает как пустую строку.
func subjectTypeFromProto(value locationv1.SubjectType) models.SubjectType {
	switch value {
	case locationv1.SubjectType_SUBJECT_TYPE_BRIGADE:
		return models.SubjectTypeBrigade
	case locationv1.SubjectType_SUBJECT_TYPE_VEHICLE:
		return models.SubjectTypeVehicle
	case locationv1.SubjectType_SUBJECT_TYPE_DEVICE:
		return models.SubjectTypeDevice
	}
	return ""
}

// sortOrderFromProto возвращает ASC только для явного ASC; остальные значения дают DESC.
func sortOrderFromProto(value locationv1.SortOrder) models.SortOrder {

	if value == locationv1.SortOrder_SORT_ORDER_ASC {
		return models.SortOrderAsc
	}

	return models.SortOrderDesc
}

// parseUUID обрезает крайние пробелы и разбирает UUID; неверный формат даёт
// uuid.Nil и InvalidArgument с именем поля.
func parseUUID(value, field string) (uuid.UUID, error) {
	id, err := uuid.Parse(strings.TrimSpace(value))

	if err != nil {
		return uuid.Nil, status.Errorf(codes.InvalidArgument, "%s must be a UUID", field)
	}

	return id, nil
}

// parseUUIDs разбирает список UUID с сохранением порядка и повторов;
// первая ошибка даёт nil и InvalidArgument, пустой вход — пустой ненулевой срез.
func parseUUIDs(values []string, field string) ([]uuid.UUID, error) {
	result := make([]uuid.UUID, 0, len(values))
	for _, value := range values {
		id, err := parseUUID(value, field)

		if err != nil {
			return nil, err
		}

		result = append(result, id)
	}
	return result, nil
}

// uuidStrings преобразует UUID в строки с сохранением порядка и повторов.
func uuidStrings(values []uuid.UUID) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.String())
	}
	return result
}

// requiredTime требует непустой корректный protobuf-timestamp и преобразует его
// в time.Time; отсутствие или неверное значение даёт InvalidArgument с именем поля.
func requiredTime(value *timestamppb.Timestamp, field string) (time.Time, error) {

	if value == nil || !value.IsValid() {
		return time.Time{}, status.Errorf(codes.InvalidArgument, "%s is required", field)
	}

	return value.AsTime(), nil
}

// actorRoles объединяет роли из всех x-actor-roles, разделяя значения запятыми;
// регистр, пробелы и пустые элементы здесь сохраняются.
func actorRoles(ctx context.Context) []string {
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("x-actor-roles")
	var result []string
	for _, value := range values {
		result = append(result, strings.Split(value, ",")...)
	}
	return result
}

// toStatus переводит ошибки валидации и геометрии в InvalidArgument, отсутствие —
// в NotFound, дубликаты и нарушение порядка позиций — в AlreadyExists, запрет —
// в PermissionDenied, недоступность зависимости — в Unavailable; прочие — в Internal.
func toStatus(err error) error {
	switch {
	case errors.Is(err, models.ErrValidation), errors.Is(err, models.ErrInvalidGeometry):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, models.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, models.ErrAlreadyExists), errors.Is(err, models.ErrOutOfOrderPosition):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, models.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, models.ErrDependencyUnavailable):
		return status.Error(codes.Unavailable, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
