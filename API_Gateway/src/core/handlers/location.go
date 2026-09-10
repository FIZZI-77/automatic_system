package handlers

import (
	"context"
	"net/http"
	"time"

	"gateway/models"

	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	"github.com/gin-gonic/gin"
)

type LocationHandler struct {
	client locationv1.LocationServiceClient
}

func NewLocationHandler(client locationv1.LocationServiceClient) *LocationHandler {
	return &LocationHandler{client: client}
}

func (h *LocationHandler) RecordPosition(c *gin.Context) {
	var req models.RecordPositionRequest
	if !bindJSON(c, &req) {
		return
	}
	occurredAt, err := ToProtoTimestamp(req.OccurredAt)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid occurred_at"})
		return
	}
	res, err := h.client.RecordPosition(locationRequestContext(c), &locationv1.RecordPositionRequest{EventId: req.EventID, EventVersion: req.EventVersion, OccurredAt: occurredAt, DeviceId: req.DeviceID, VehicleId: req.VehicleID, BrigadeId: req.BrigadeID, Sequence: req.Sequence, Latitude: req.Latitude, Longitude: req.Longitude, SpeedKmh: req.SpeedKMH, Heading: req.Heading, AccuracyMeters: req.AccuracyMeters, AltitudeMeters: req.AltitudeMeters, Simulated: req.Simulated})
	if err != nil {
		locationResponse(c, 0, err, nil)
		return
	}
	locationResponse(c, http.StatusCreated, nil, gin.H{"position": fromProtoPosition(res.GetPosition()), "duplicate": res.GetDuplicate()})
}

func (h *LocationHandler) GetCurrentLocation(c *gin.Context) {
	var req models.GetCurrentLocationRequest
	if !bindJSON(c, &req) {
		return
	}
	res, err := h.client.GetCurrentLocation(locationRequestContext(c), &locationv1.GetCurrentLocationRequest{SubjectType: toProtoSubjectType(req.SubjectType), SubjectId: req.SubjectID})
	if err != nil {
		locationResponse(c, 0, err, nil)
		return
	}
	locationResponse(c, http.StatusOK, nil, gin.H{"location": fromProtoCurrentLocation(res.GetLocation())})
}

func (h *LocationHandler) GetCurrentLocations(c *gin.Context) {
	var req models.GetCurrentLocationsRequest
	if !bindJSON(c, &req) {
		return
	}
	res, err := h.client.GetCurrentLocations(locationRequestContext(c), &locationv1.GetCurrentLocationsRequest{BrigadeIds: req.BrigadeIDs, AllowStale: req.AllowStale})
	if err != nil {
		locationResponse(c, 0, err, nil)
		return
	}
	locations := make(map[string]*models.CurrentLocation, len(res.GetLocations()))
	for id, value := range res.GetLocations() {
		locations[id] = fromProtoCurrentLocation(value)
	}
	locationResponse(c, http.StatusOK, nil, gin.H{"locations": locations, "missing_brigade_ids": res.GetMissingBrigadeIds()})
}

func (h *LocationHandler) ListPositionHistory(c *gin.Context) {
	var req models.ListPositionHistoryRequest
	if !bindJSON(c, &req) {
		return
	}
	from, err := ToProtoTimestamp(req.From)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid from"})
		return
	}
	to, err := ToProtoTimestamp(req.To)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid to"})
		return
	}
	res, err := h.client.ListPositionHistory(locationRequestContext(c), &locationv1.ListPositionHistoryRequest{BrigadeId: req.BrigadeID, From: from, To: to, Limit: req.Limit, Offset: req.Offset, Order: toProtoLocationSortOrder(req.Order)})
	if err != nil {
		locationResponse(c, 0, err, nil)
		return
	}
	positions := make([]*models.Position, 0, len(res.GetPositions()))
	for _, value := range res.GetPositions() {
		positions = append(positions, fromProtoPosition(value))
	}
	locationResponse(c, http.StatusOK, nil, gin.H{"positions": positions, "total": res.GetTotal()})
}

func (h *LocationHandler) FindNearbyBrigades(c *gin.Context) {
	var req models.FindNearbyBrigadesRequest
	if !bindJSON(c, &req) {
		return
	}
	res, err := h.client.FindNearbyBrigades(locationRequestContext(c), &locationv1.FindNearbyBrigadesRequest{Latitude: req.Latitude, Longitude: req.Longitude, RadiusMeters: req.RadiusMeters, BrigadeIds: req.BrigadeIDs, OnlyFresh: req.OnlyFresh, FreshnessWindowSeconds: req.FreshnessWindowSeconds, Limit: req.Limit})
	if err != nil {
		locationResponse(c, 0, err, nil)
		return
	}
	brigades := make([]*models.NearbyBrigade, 0, len(res.GetBrigades()))
	for _, value := range res.GetBrigades() {
		brigades = append(brigades, &models.NearbyBrigade{BrigadeID: value.GetBrigadeId(), Location: fromProtoCurrentLocation(value.GetLocation()), DistanceMeters: value.GetDistanceMeters()})
	}
	locationResponse(c, http.StatusOK, nil, gin.H{"brigades": brigades})
}

func (h *LocationHandler) CreateGeoZone(c *gin.Context) {
	var req models.CreateGeoZoneRequest
	if !bindJSON(c, &req) {
		return
	}
	res, err := h.client.CreateGeoZone(locationRequestContext(c), &locationv1.CreateGeoZoneRequest{DepartmentId: req.DepartmentID, Name: req.Name, GeoJson: req.GeoJSON})
	if err != nil {
		locationResponse(c, 0, err, nil)
		return
	}
	locationResponse(c, http.StatusCreated, nil, gin.H{"zone": fromProtoGeoZone(res.GetZone())})
}

func (h *LocationHandler) UpdateGeoZone(c *gin.Context) {
	var req models.UpdateGeoZoneRequest
	if !bindJSON(c, &req) {
		return
	}
	if req.Name == nil && req.GeoJSON == nil && req.Active == nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "at least one field must be provided"})
		return
	}
	res, err := h.client.UpdateGeoZone(locationRequestContext(c), &locationv1.UpdateGeoZoneRequest{Id: req.ID, Name: req.Name, GeoJson: req.GeoJSON, Active: req.Active})
	if err != nil {
		locationResponse(c, 0, err, nil)
		return
	}
	locationResponse(c, http.StatusOK, nil, gin.H{"zone": fromProtoGeoZone(res.GetZone())})
}

func (h *LocationHandler) DeleteGeoZone(c *gin.Context) {
	var req models.DeleteGeoZoneRequest
	if !bindJSON(c, &req) {
		return
	}
	res, err := h.client.DeleteGeoZone(locationRequestContext(c), &locationv1.DeleteGeoZoneRequest{Id: req.ID})
	if err != nil {
		locationResponse(c, 0, err, nil)
		return
	}
	locationResponse(c, http.StatusOK, nil, gin.H{"zone": fromProtoGeoZone(res.GetZone())})
}

func (h *LocationHandler) ListGeoZones(c *gin.Context) {
	var req models.ListGeoZonesRequest
	if !bindJSON(c, &req) {
		return
	}
	res, err := h.client.ListGeoZones(locationRequestContext(c), &locationv1.ListGeoZonesRequest{DepartmentId: req.DepartmentID, Active: req.Active, Limit: req.Limit, Offset: req.Offset})
	if err != nil {
		locationResponse(c, 0, err, nil)
		return
	}
	locationResponse(c, http.StatusOK, nil, gin.H{"zones": fromProtoGeoZones(res.GetZones()), "total": res.GetTotal()})
}

func (h *LocationHandler) CheckPointInZones(c *gin.Context) {
	var req models.CheckPointInZonesRequest
	if !bindJSON(c, &req) {
		return
	}
	res, err := h.client.CheckPointInZones(locationRequestContext(c), &locationv1.CheckPointInZonesRequest{Latitude: req.Latitude, Longitude: req.Longitude, DepartmentId: req.DepartmentID, ZoneIds: req.ZoneIDs})
	if err != nil {
		locationResponse(c, 0, err, nil)
		return
	}
	locationResponse(c, http.StatusOK, nil, gin.H{"zones": fromProtoGeoZones(res.GetZones())})
}

func locationRequestContext(c *gin.Context) context.Context {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	c.Set("location_cancel", cancel)
	return gatewayActorContext(ctx, c)
}

func locationResponse(c *gin.Context, statusCode int, err error, response any) {
	if value, ok := c.Get("location_cancel"); ok {
		if cancel, ok := value.(context.CancelFunc); ok {
			cancel()
		}
	}
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	c.JSON(statusCode, response)
}
