package repository

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"location/models"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	defaultCurrentLocationTTL = 24 * time.Hour
	defaultStaleAfter         = 15 * time.Second
	defaultOfflineAfter       = 60 * time.Second

	brigadeGeoKey     = "locations:brigades:geo"
	signalLastSeenKey = "locations:signal:last_seen"
	signalEventsKey   = "locations:events"
)

var saveCurrentLocationScript = redis.NewScript(`
local previous_sequence = redis.call("HGET", KEYS[1], "sequence")
local previous_event_id = redis.call("HGET", KEYS[1], "event_id")

if previous_event_id and previous_event_id == ARGV[1] then
    return 2
end

if previous_sequence then
    local incoming_sequence = ARGV[5]
    if string.len(incoming_sequence) < string.len(previous_sequence)
        or (
            string.len(incoming_sequence) == string.len(previous_sequence)
            and incoming_sequence <= previous_sequence
        ) then
        return 0
    end
end

redis.call("HSET", KEYS[1],
    "event_id", ARGV[1],
    "device_id", ARGV[2],
    "vehicle_id", ARGV[3],
    "brigade_id", ARGV[4],
    "sequence", ARGV[5],
    "latitude", ARGV[6],
    "longitude", ARGV[7],
    "speed_kmh", ARGV[8],
    "heading", ARGV[9],
    "accuracy_meters", ARGV[10],
    "altitude_meters", ARGV[11],
    "simulated", ARGV[12],
    "recorded_at", ARGV[13],
    "received_at", ARGV[14],
    "received_at_unix_ms", ARGV[15],
    "signal_status", ARGV[16],
    "stale_after", ARGV[17])
redis.call("EXPIRE", KEYS[1], ARGV[18])
redis.call("SET", KEYS[2], ARGV[4], "EX", ARGV[18])
redis.call("SET", KEYS[3], ARGV[4], "EX", ARGV[18])
redis.call("GEOADD", KEYS[4], ARGV[7], ARGV[6], ARGV[4])
redis.call("ZADD", KEYS[5], ARGV[15], ARGV[4])
return 1
`)

var updateSignalStatusScript = redis.NewScript(`
local received_at = redis.call("HGET", KEYS[1], "received_at_unix_ms")
if not received_at then
    redis.call("ZREM", KEYS[2], ARGV[1])
    redis.call("ZREM", KEYS[3], ARGV[1])
    return {0, "", ""}
end

local current_status = redis.call("HGET", KEYS[1], "signal_status") or "ONLINE"
local new_status = current_status
if tonumber(received_at) <= tonumber(ARGV[3]) then
    new_status = "OFFLINE"
elseif tonumber(received_at) <= tonumber(ARGV[2]) then
    new_status = "STALE"
end

if new_status == "OFFLINE" then
    redis.call("ZREM", KEYS[2], ARGV[1])
    redis.call("ZREM", KEYS[3], ARGV[1])
end
if new_status == current_status then
    return {0, current_status, new_status}
end

redis.call("HSET", KEYS[1], "signal_status", new_status)
if new_status == "OFFLINE" then
    redis.call("XADD", KEYS[4], "MAXLEN", "~", 100000, "*",
        "event_type", "BrigadeSignalLost",
        "event_version", "1",
        "brigade_id", ARGV[1],
        "from_status", current_status,
        "to_status", new_status,
        "occurred_at", ARGV[4])
end
return {1, current_status, new_status}
`)

type CurrentLocationRepoConfig struct {
	CurrentLocationTTL time.Duration
	StaleAfter         time.Duration
	OfflineAfter       time.Duration
}

type CurrentLocationRepoStruct struct {
	rdb redis.UniversalClient
	cfg CurrentLocationRepoConfig
	now func() time.Time
}

func NewCurrentLocationRepo(rdb redis.UniversalClient) *CurrentLocationRepoStruct {
	return NewCurrentLocationRepoWithConfig(rdb, CurrentLocationRepoConfig{})
}

func NewCurrentLocationRepoWithConfig(
	rdb redis.UniversalClient,
	cfg CurrentLocationRepoConfig,
) *CurrentLocationRepoStruct {
	if cfg.CurrentLocationTTL <= 0 {
		cfg.CurrentLocationTTL = defaultCurrentLocationTTL
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = defaultStaleAfter
	}
	if cfg.OfflineAfter <= cfg.StaleAfter {
		cfg.OfflineAfter = max(defaultOfflineAfter, 4*cfg.StaleAfter)
	}
	if cfg.CurrentLocationTTL <= cfg.OfflineAfter {
		cfg.CurrentLocationTTL = 2 * cfg.OfflineAfter
	}
	return &CurrentLocationRepoStruct{rdb: rdb, cfg: cfg, now: time.Now}
}

func (c *CurrentLocationRepoStruct) SaveCurrentLocation(
	ctx context.Context,
	in *models.RecordPositionInput,
) (*models.CurrentLocation, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("repository: SaveCurrentLocation: %w: %v", models.ErrValidation, err)
	}
	if c.rdb == nil {
		return nil, fmt.Errorf(
			"repository: SaveCurrentLocation: %w",
			models.ErrDependencyUnavailable,
		)
	}

	receivedAt := c.now().UTC()
	recordedAt := in.OccurredAt.UTC()
	staleAfter := receivedAt.Add(c.cfg.StaleAfter)
	altitude := ""
	if in.AltitudeMeters != nil {
		altitude = strconv.FormatFloat(*in.AltitudeMeters, 'g', -1, 64)
	}
	keys := []string{
		brigadeLocationKey(in.BrigadeID),
		deviceBrigadeKey(in.DeviceID),
		vehicleBrigadeKey(in.VehicleID),
		brigadeGeoKey,
		signalLastSeenKey,
	}
	result, err := saveCurrentLocationScript.Run(
		ctx,
		c.rdb,
		keys,
		in.EventID.String(),
		strings.TrimSpace(in.DeviceID),
		in.VehicleID.String(),
		in.BrigadeID.String(),
		strconv.FormatUint(in.Sequence, 10),
		in.Latitude,
		in.Longitude,
		in.SpeedKMH,
		in.Heading,
		in.AccuracyMeters,
		altitude,
		strconv.FormatBool(in.Simulated),
		recordedAt.Format(time.RFC3339Nano),
		receivedAt.Format(
			time.RFC3339Nano,
		),
		receivedAt.UnixMilli(),
		string(models.SignalStatusOnline),
		staleAfter.Format(time.RFC3339Nano),
		int64(c.cfg.CurrentLocationTTL/time.Second),
	).Int()
	if err != nil {
		return nil, fmt.Errorf("repository: SaveCurrentLocation: redis script: %w", err)
	}
	if result == 0 {
		return nil, models.ErrOutOfOrderPosition
	}
	if result == 2 {
		stored, getErr := c.getByBrigadeID(ctx, in.BrigadeID)
		if getErr != nil {
			return nil, fmt.Errorf("repository: SaveCurrentLocation: read duplicate: %w", getErr)
		}
		stored.Duplicate = true
		return stored, nil
	}

	return &models.CurrentLocation{
		Position: &models.Position{
			ID: uuid.New(), EventID: in.EventID, DeviceID: strings.TrimSpace(in.DeviceID), VehicleID: in.VehicleID,
			BrigadeID: in.BrigadeID, Sequence: in.Sequence, Latitude: in.Latitude, Longitude: in.Longitude,
			SpeedKMH: in.SpeedKMH, Heading: in.Heading, AccuracyMeters: in.AccuracyMeters,
			AltitudeMeters: in.AltitudeMeters, Simulated: in.Simulated, RecordedAt: recordedAt, ReceivedAt: receivedAt,
		},
		SignalStatus: models.SignalStatusOnline,
		StaleAfter:   staleAfter,
	}, nil
}

func (c *CurrentLocationRepoStruct) GetCurrentLocation(
	ctx context.Context,
	in *models.GetCurrentLocationInput,
) (*models.GetCurrentLocationResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("repository: GetCurrentLocation: %w: %v", models.ErrValidation, err)
	}
	if c.rdb == nil {
		return nil, fmt.Errorf(
			"repository: GetCurrentLocation: %w",
			models.ErrDependencyUnavailable,
		)
	}

	brigadeID, err := c.resolveBrigadeID(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("repository: GetCurrentLocation: %w", err)
	}
	location, err := c.getByBrigadeID(ctx, brigadeID)
	if err != nil {
		return nil, fmt.Errorf("repository: GetCurrentLocation: %w", err)
	}
	return &models.GetCurrentLocationResult{Location: location}, nil
}

func (c *CurrentLocationRepoStruct) GetCurrentLocations(
	ctx context.Context,
	in *models.GetCurrentLocationsInput,
) (*models.GetCurrentLocationsResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("repository: GetCurrentLocations: %w: %v", models.ErrValidation, err)
	}
	if c.rdb == nil {
		return nil, fmt.Errorf(
			"repository: GetCurrentLocations: %w",
			models.ErrDependencyUnavailable,
		)
	}

	unique := make([]uuid.UUID, 0, len(in.BrigadeIDs))
	seen := make(map[uuid.UUID]struct{}, len(in.BrigadeIDs))
	for _, brigadeID := range in.BrigadeIDs {
		if _, exists := seen[brigadeID]; !exists {
			seen[brigadeID] = struct{}{}
			unique = append(unique, brigadeID)
		}
	}

	pipe := c.rdb.Pipeline()
	commands := make(map[uuid.UUID]*redis.MapStringStringCmd, len(unique))
	for _, brigadeID := range unique {
		commands[brigadeID] = pipe.HGetAll(ctx, brigadeLocationKey(brigadeID))
	}
	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("repository: GetCurrentLocations: pipeline: %w", err)
	}

	result := &models.GetCurrentLocationsResult{
		Locations: make(map[uuid.UUID]*models.CurrentLocation, len(unique)),
	}
	for _, brigadeID := range unique {
		values, cmdErr := commands[brigadeID].Result()
		if cmdErr != nil || len(values) == 0 {
			result.Missing = append(result.Missing, brigadeID)
			continue
		}
		location, parseErr := c.decodeCurrentLocation(values)
		if parseErr != nil {
			return nil, fmt.Errorf(
				"repository: GetCurrentLocations: brigade %s: %w",
				brigadeID,
				parseErr,
			)
		}
		if !in.AllowStale && location.SignalStatus != models.SignalStatusOnline {
			result.Missing = append(result.Missing, brigadeID)
			continue
		}
		result.Locations[brigadeID] = location
	}
	return result, nil
}

func (c *CurrentLocationRepoStruct) FindNearbyBrigades(
	ctx context.Context,
	in *models.FindNearbyBrigadesInput,
) (*models.FindNearbyBrigadesResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("repository: FindNearbyBrigades: %w: %v", models.ErrValidation, err)
	}
	if c.rdb == nil {
		return nil, fmt.Errorf(
			"repository: FindNearbyBrigades: %w",
			models.ErrDependencyUnavailable,
		)
	}
	limit := int(in.Limit)
	if limit <= 0 {
		limit = int(models.DefaultLimit)
	}
	query := &redis.GeoSearchLocationQuery{
		GeoSearchQuery: redis.GeoSearchQuery{
			Longitude:  in.Longitude,
			Latitude:   in.Latitude,
			Radius:     in.RadiusMeters,
			RadiusUnit: "m",
			Sort:       "ASC",
		},
		WithCoord: true,
		WithDist:  true,
	}
	if len(in.BrigadeIDs) == 0 && !in.OnlyFresh {
		query.Count = limit
	}
	geoLocations, err := c.rdb.GeoSearchLocation(ctx, brigadeGeoKey, query).Result()
	if err != nil {
		return nil, fmt.Errorf("repository: FindNearbyBrigades: geo search: %w", err)
	}

	allowed := make(map[uuid.UUID]struct{}, len(in.BrigadeIDs))
	for _, brigadeID := range in.BrigadeIDs {
		allowed[brigadeID] = struct{}{}
	}
	candidateIDs := make([]uuid.UUID, 0, len(geoLocations))
	distances := make(map[uuid.UUID]float64, len(geoLocations))
	for _, item := range geoLocations {
		brigadeID, parseErr := uuid.Parse(item.Name)
		if parseErr != nil {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[brigadeID]; !ok {
				continue
			}
		}
		candidateIDs = append(candidateIDs, brigadeID)
		distances[brigadeID] = item.Dist
	}
	if len(candidateIDs) == 0 {
		return &models.FindNearbyBrigadesResult{Brigades: []*models.NearbyBrigade{}}, nil
	}
	locations, err := c.GetCurrentLocations(
		ctx,
		&models.GetCurrentLocationsInput{BrigadeIDs: candidateIDs, AllowStale: true},
	)
	if err != nil {
		return nil, fmt.Errorf("repository: FindNearbyBrigades: load locations: %w", err)
	}
	freshnessWindow := in.FreshnessWindow
	if freshnessWindow <= 0 {
		freshnessWindow = c.cfg.StaleAfter
	}
	result := &models.FindNearbyBrigadesResult{
		Brigades: make([]*models.NearbyBrigade, 0, min(limit, len(candidateIDs))),
	}
	now := c.now()
	for _, brigadeID := range candidateIDs {
		location, ok := locations.Locations[brigadeID]
		if !ok {
			continue
		}
		if in.OnlyFresh && now.Sub(location.Position.ReceivedAt) > freshnessWindow {
			continue
		}
		result.Brigades = append(
			result.Brigades,
			&models.NearbyBrigade{
				BrigadeID:      brigadeID,
				Location:       location,
				DistanceMeters: distances[brigadeID],
			},
		)
		if len(result.Brigades) == limit {
			break
		}
	}
	return result, nil
}

func (c *CurrentLocationRepoStruct) DetectLostSignals(
	ctx context.Context,
	in *models.DetectLostSignalsInput,
) (*models.DetectLostSignalsResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("repository: DetectLostSignals: %w: %v", models.ErrValidation, err)
	}
	if c.rdb == nil {
		return nil, fmt.Errorf("repository: DetectLostSignals: %w", models.ErrDependencyUnavailable)
	}
	limit := int64(in.Limit)
	if limit <= 0 {
		limit = int64(models.DefaultLimit)
	}
	brigadeIDs, err := c.rdb.ZRangeByScore(ctx, signalLastSeenKey, &redis.ZRangeBy{
		Min: "-inf", Max: strconv.FormatInt(in.StaleBefore.UnixMilli(), 10), Offset: 0, Count: limit,
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("repository: DetectLostSignals: find candidates: %w", err)
	}

	result := &models.DetectLostSignalsResult{
		Changes: make([]*models.SignalChange, 0, len(brigadeIDs)),
	}
	changedAt := c.now().UTC()
	for _, rawID := range brigadeIDs {
		brigadeID, parseErr := uuid.Parse(rawID)
		if parseErr != nil {
			_ = c.rdb.ZRem(ctx, signalLastSeenKey, rawID).Err()
			continue
		}
		value, scriptErr := updateSignalStatusScript.Run(
			ctx,
			c.rdb,
			[]string{
				brigadeLocationKey(brigadeID),
				signalLastSeenKey,
				brigadeGeoKey,
				signalEventsKey,
			},
			rawID,
			in.StaleBefore.UnixMilli(),
			in.OfflineBefore.UnixMilli(),
			changedAt.Format(time.RFC3339Nano),
		).Result()
		if scriptErr != nil {
			return nil, fmt.Errorf(
				"repository: DetectLostSignals: brigade %s: %w",
				brigadeID,
				scriptErr,
			)
		}
		parts, ok := value.([]interface{})
		if !ok || len(parts) != 3 || toInt64(parts[0]) != 1 {
			continue
		}
		result.Changes = append(result.Changes, &models.SignalChange{
			BrigadeID: brigadeID,
			From:      models.SignalStatus(toString(parts[1])),
			To:        models.SignalStatus(toString(parts[2])),
			ChangedAt: changedAt,
		})
	}
	return result, nil
}

func (c *CurrentLocationRepoStruct) resolveBrigadeID(
	ctx context.Context,
	in *models.GetCurrentLocationInput,
) (uuid.UUID, error) {
	if in.SubjectType == models.SubjectTypeBrigade {
		brigadeID, err := uuid.Parse(strings.TrimSpace(in.SubjectID))
		if err != nil {
			return uuid.Nil, fmt.Errorf("invalid brigade id: %w", models.ErrValidation)
		}
		return brigadeID, nil
	}
	key := deviceBrigadeKey(in.SubjectID)
	if in.SubjectType == models.SubjectTypeVehicle {
		vehicleID, err := uuid.Parse(strings.TrimSpace(in.SubjectID))
		if err != nil {
			return uuid.Nil, fmt.Errorf("invalid vehicle id: %w", models.ErrValidation)
		}
		key = vehicleBrigadeKey(vehicleID)
	}
	value, err := c.rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return uuid.Nil, models.ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	brigadeID, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, fmt.Errorf("corrupt brigade mapping: %w", err)
	}
	return brigadeID, nil
}

func (c *CurrentLocationRepoStruct) getByBrigadeID(
	ctx context.Context,
	brigadeID uuid.UUID,
) (*models.CurrentLocation, error) {
	values, err := c.rdb.HGetAll(ctx, brigadeLocationKey(brigadeID)).Result()
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, models.ErrNotFound
	}
	return c.decodeCurrentLocation(values)
}

func (c *CurrentLocationRepoStruct) decodeCurrentLocation(
	values map[string]string,
) (*models.CurrentLocation, error) {
	eventID, err := uuid.Parse(values["event_id"])
	if err != nil {
		return nil, fmt.Errorf("decode event_id: %w", err)
	}
	vehicleID, err := uuid.Parse(values["vehicle_id"])
	if err != nil {
		return nil, fmt.Errorf("decode vehicle_id: %w", err)
	}
	brigadeID, err := uuid.Parse(values["brigade_id"])
	if err != nil {
		return nil, fmt.Errorf("decode brigade_id: %w", err)
	}
	sequence, err := strconv.ParseUint(values["sequence"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("decode sequence: %w", err)
	}
	latitude, err := parseFloatField(values, "latitude")
	if err != nil {
		return nil, err
	}
	longitude, err := parseFloatField(values, "longitude")
	if err != nil {
		return nil, err
	}
	speed, err := parseFloatField(values, "speed_kmh")
	if err != nil {
		return nil, err
	}
	heading, err := parseFloatField(values, "heading")
	if err != nil {
		return nil, err
	}
	accuracy, err := parseFloatField(values, "accuracy_meters")
	if err != nil {
		return nil, err
	}
	recordedAt, err := time.Parse(time.RFC3339Nano, values["recorded_at"])
	if err != nil {
		return nil, fmt.Errorf("decode recorded_at: %w", err)
	}
	receivedAt, err := time.Parse(time.RFC3339Nano, values["received_at"])
	if err != nil {
		return nil, fmt.Errorf("decode received_at: %w", err)
	}
	staleAfter, err := time.Parse(time.RFC3339Nano, values["stale_after"])
	if err != nil {
		return nil, fmt.Errorf("decode stale_after: %w", err)
	}
	simulated, err := strconv.ParseBool(values["simulated"])
	if err != nil {
		return nil, fmt.Errorf("decode simulated: %w", err)
	}
	var altitude *float64
	if raw := values["altitude_meters"]; raw != "" {
		value, parseErr := strconv.ParseFloat(raw, 64)
		if parseErr != nil {
			return nil, fmt.Errorf("decode altitude_meters: %w", parseErr)
		}
		altitude = &value
	}
	status := models.SignalStatus(values["signal_status"])
	if status != models.SignalStatusOnline && status != models.SignalStatusStale &&
		status != models.SignalStatusOffline {
		return nil, fmt.Errorf("decode signal_status: invalid value %q", status)
	}
	now := c.now()
	if now.Sub(receivedAt) >= c.cfg.OfflineAfter {
		status = models.SignalStatusOffline
	} else if !now.Before(staleAfter) {
		status = models.SignalStatusStale
	}
	return &models.CurrentLocation{
		Position: &models.Position{
			EventID:        eventID,
			DeviceID:       values["device_id"],
			VehicleID:      vehicleID,
			BrigadeID:      brigadeID,
			Sequence:       sequence,
			Latitude:       latitude,
			Longitude:      longitude,
			SpeedKMH:       speed,
			Heading:        heading,
			AccuracyMeters: accuracy,
			AltitudeMeters: altitude,
			Simulated:      simulated,
			RecordedAt:     recordedAt,
			ReceivedAt:     receivedAt,
		},
		SignalStatus: status, StaleAfter: staleAfter,
	}, nil
}

func brigadeLocationKey(
	brigadeID uuid.UUID,
) string {
	return "location:brigade:" + brigadeID.String()
}
func deviceBrigadeKey(deviceID string) string {
	return "location:device:" + strings.TrimSpace(deviceID) + ":brigade"
}
func vehicleBrigadeKey(vehicleID uuid.UUID) string {
	return "location:vehicle:" + vehicleID.String() + ":brigade"
}

func parseFloatField(values map[string]string, field string) (float64, error) {
	value, err := strconv.ParseFloat(values[field], 64)
	if err != nil {
		return 0, fmt.Errorf("decode %s: %w", field, err)
	}
	return value, nil
}

func toInt64(value interface{}) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case string:
		parsed, _ := strconv.ParseInt(typed, 10, 64)
		return parsed
	default:
		return 0
	}
}

func toString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return fmt.Sprint(value)
	}
}
