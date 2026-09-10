package repository

import (
	"context"
	"fmt"
	"strings"

	"location/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type GeoZoneRepoStruct struct{ writePool, readPool *pgxpool.Pool }

func NewGeoZoneRepo(writePool, readPool *pgxpool.Pool) *GeoZoneRepoStruct {
	if readPool == nil {
		readPool = writePool
	}
	return &GeoZoneRepoStruct{writePool: writePool, readPool: readPool}
}

func (r *GeoZoneRepoStruct) CreateGeoZone(
	ctx context.Context,
	in *models.CreateGeoZoneInput,
) (*models.CreateGeoZoneResult, error) {
	row := r.writePool.QueryRow(ctx, `INSERT INTO geo_zones(department_id,name,zone)
		VALUES($1,btrim($2),ST_SetSRID(ST_GeomFromGeoJSON($3),4326)::geography)
		RETURNING id,department_id,name,ST_AsGeoJSON(zone::geometry),active,created_at,updated_at`,
		in.DepartmentID,
		in.Name,
		in.GeoJSON,
	)
	zone, err := scanGeoZone(row)
	if err != nil {
		return nil, mapGeoZoneError("CreateGeoZone", err)
	}
	return &models.CreateGeoZoneResult{Zone: zone}, nil
}

func (r *GeoZoneRepoStruct) UpdateGeoZone(
	ctx context.Context,
	in *models.UpdateGeoZoneInput,
) (*models.UpdateGeoZoneResult, error) {
	row := r.writePool.QueryRow(ctx, `UPDATE geo_zones SET name=COALESCE(btrim($2),name),
		zone=CASE WHEN $3::text IS NULL THEN zone ELSE ST_SetSRID(ST_GeomFromGeoJSON($3),4326)::geography END,
		active=COALESCE($4,active),updated_at=now() WHERE id=$1
		RETURNING id,department_id,name,ST_AsGeoJSON(zone::geometry),active,created_at,updated_at`,
		in.ID,
		in.Name,
		in.GeoJSON,
		in.Active,
	)
	zone, err := scanGeoZone(row)
	if err != nil {
		return nil, mapGeoZoneError("UpdateGeoZone", err)
	}
	return &models.UpdateGeoZoneResult{Zone: zone}, nil
}

func (r *GeoZoneRepoStruct) DeleteGeoZone(
	ctx context.Context,
	in *models.DeleteGeoZoneInput,
) (*models.DeleteGeoZoneResult, error) {
	row := r.writePool.QueryRow(ctx, `UPDATE geo_zones SET active=false,updated_at=now() WHERE id=$1
		RETURNING id,department_id,name,ST_AsGeoJSON(zone::geometry),active,created_at,updated_at`, in.ID)
	zone, err := scanGeoZone(row)
	if err != nil {
		return nil, mapGeoZoneError("DeleteGeoZone", err)
	}
	return &models.DeleteGeoZoneResult{Zone: zone}, nil
}

func (r *GeoZoneRepoStruct) ListGeoZones(
	ctx context.Context,
	in *models.ListGeoZonesInput,
) (*models.ListGeoZonesResult, error) {
	where := []string{"true"}
	args := []any{}
	if in.DepartmentID != nil {
		args = append(args, *in.DepartmentID)
		where = append(where, fmt.Sprintf("department_id=$%d", len(args)))
	}
	if in.Active != nil {
		args = append(args, *in.Active)
		where = append(where, fmt.Sprintf("active=$%d", len(args)))
	}
	clause := strings.Join(where, " AND ")
	var total int64
	if err := r.readPool.QueryRow(ctx, "SELECT count(*) FROM geo_zones WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("repository: ListGeoZones: count: %w", err)
	}
	limit := in.Limit
	if limit <= 0 {
		limit = models.DefaultLimit
	}
	args = append(args, limit, in.Offset)
	rows, err := r.readPool.Query(
		ctx,
		"SELECT id,department_id,name,ST_AsGeoJSON(zone::geometry),"+
			"active,created_at,updated_at FROM geo_zones WHERE "+clause+fmt.Sprintf(
			" ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
			len(args)-1,
			len(args),
		),
		args...)
	if err != nil {
		return nil, fmt.Errorf("repository: ListGeoZones: query: %w", err)
	}
	defer rows.Close()
	result := &models.ListGeoZonesResult{Zones: make([]*models.GeoZone, 0, limit), Total: total}
	for rows.Next() {
		zone, scanErr := scanGeoZone(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result.Zones = append(result.Zones, zone)
	}
	return result, rows.Err()
}

func (r *GeoZoneRepoStruct) CheckPointInZones(
	ctx context.Context,
	in *models.CheckPointInZonesInput,
) (*models.CheckPointInZonesResult, error) {
	args := []any{in.Longitude, in.Latitude}
	where := []string{
		"active=true",
		"ST_Covers(zone,ST_SetSRID(ST_MakePoint($1,$2),4326)::geography)",
	}
	if in.DepartmentID != nil {
		args = append(args, *in.DepartmentID)
		where = append(where, fmt.Sprintf("department_id=$%d", len(args)))
	}
	if len(in.ZoneIDs) > 0 {
		args = append(args, in.ZoneIDs)
		where = append(where, fmt.Sprintf("id=ANY($%d)", len(args)))
	}
	rows, err := r.readPool.Query(
		ctx,
		"SELECT id,department_id,name,ST_AsGeoJSON(zone::geometry),"+
			"active,created_at,updated_at FROM geo_zones WHERE "+strings.Join(
			where,
			" AND ",
		)+" ORDER BY name",
		args...)
	if err != nil {
		return nil, fmt.Errorf("repository: CheckPointInZones: %w", err)
	}
	defer rows.Close()
	result := &models.CheckPointInZonesResult{Zones: []*models.GeoZone{}}
	for rows.Next() {
		zone, scanErr := scanGeoZone(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result.Zones = append(result.Zones, zone)
	}
	return result, rows.Err()
}

type rowScanner interface{ Scan(...any) error }

func scanGeoZone(row rowScanner) (*models.GeoZone, error) {
	zone := new(models.GeoZone)
	if err := row.Scan(
		&zone.ID,
		&zone.DepartmentID,
		&zone.Name,
		&zone.GeoJSON,
		&zone.Active,
		&zone.CreatedAt,
		&zone.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return zone, nil
}
func mapGeoZoneError(operation string, err error) error {
	if err == pgx.ErrNoRows {
		return fmt.Errorf("repository: %s: %w", operation, models.ErrNotFound)
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "geometry") || strings.Contains(message, "parse error") {
		return fmt.Errorf("repository: %s: %w: %v", operation, models.ErrInvalidGeometry, err)
	}
	if strings.Contains(message, "duplicate key") {
		return fmt.Errorf("repository: %s: %w", operation, models.ErrAlreadyExists)
	}
	return fmt.Errorf("repository: %s: %w", operation, err)
}
