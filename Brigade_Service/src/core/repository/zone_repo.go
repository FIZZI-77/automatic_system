package repository

import (
	"brigade/models"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type ZoneRepoStruct struct {
	db *sql.DB
}

func NewZoneRepo(db *sql.DB) *ZoneRepoStruct {
	return &ZoneRepoStruct{db: db}
}

func (z *ZoneRepoStruct) GetBrigadeZoneByID(ctx context.Context, zoneID uuid.UUID) (*models.BrigadeZone, error) {
	const query = `
		SELECT
			id,
			brigade_id,
			department_id,
			name,
			ST_AsGeoJSON(zone::geometry),
			priority,
			active,
			created_at,
			updated_at
		FROM brigade_zones
		WHERE id = $1
	`

	return scanBrigadeZone(z.db.QueryRowContext(ctx, query, zoneID))
}

func (z *ZoneRepoStruct) CreateBrigadeZone(ctx context.Context, in *models.CreateBrigadeZoneInput) (*models.CreateBrigadeZoneResult, error) {
	tx, err := z.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repo: CreateBrigadeZone: begin tx: %w", err)
	}
	defer tx.Rollback()

	const query = `
		INSERT INTO brigade_zones (
			brigade_id,
			department_id,
			name,
			zone,
			priority
		)
		VALUES ($1, $2, $3, ST_GeomFromGeoJSON($4)::geography, $5)
		RETURNING
			id,
			brigade_id,
			department_id,
			name,
			ST_AsGeoJSON(zone::geometry),
			priority,
			active,
			created_at,
			updated_at
	`

	zone, err := scanBrigadeZone(tx.QueryRowContext(ctx, query, in.BrigadeID, in.DepartmentID, in.Name, in.GeoJSON, in.Priority))
	if err != nil {
		return nil, fmt.Errorf("repo: CreateBrigadeZone: scan zone: %w", err)
	}

	payload := map[string]any{
		"event_id":      uuid.NewString(),
		"event_type":    "BrigadeZoneCreated",
		"zone_id":       zone.ID.String(),
		"brigade_id":    zone.BrigadeID.String(),
		"department_id": zone.DepartmentID.String(),
		"name":          zone.Name,
		"priority":      zone.Priority,
		"created_at":    zone.CreatedAt,
	}
	if err = insertOutboxEvent(ctx, tx, "brigade", zone.BrigadeID, "BrigadeZoneCreated", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: CreateBrigadeZone: insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repo: CreateBrigadeZone: commit tx: %w", err)
	}

	return &models.CreateBrigadeZoneResult{Zone: zone}, nil
}

func (z *ZoneRepoStruct) UpdateBrigadeZone(ctx context.Context, in *models.UpdateBrigadeZoneInput) (*models.UpdateBrigadeZoneResult, error) {
	tx, err := z.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repo: UpdateBrigadeZone: begin tx: %w", err)
	}
	defer tx.Rollback()

	const query = `
		UPDATE brigade_zones
		SET
			name = COALESCE($1, name),
			zone = CASE WHEN $2::text IS NULL THEN zone ELSE ST_GeomFromGeoJSON($2)::geography END,
			priority = COALESCE($3, priority),
			active = COALESCE($4, active),
			updated_at = now()
		WHERE id = $5
		RETURNING
			id,
			brigade_id,
			department_id,
			name,
			ST_AsGeoJSON(zone::geometry),
			priority,
			active,
			created_at,
			updated_at
	`

	zone, err := scanBrigadeZone(tx.QueryRowContext(ctx, query, in.Name, in.GeoJSON, in.Priority, in.Active, in.ID))
	if err != nil {
		return nil, fmt.Errorf("repo: UpdateBrigadeZone: scan zone: %w", err)
	}

	payload := map[string]any{
		"event_id":   uuid.NewString(),
		"event_type": "BrigadeZoneUpdated",
		"zone_id":    zone.ID.String(),
		"brigade_id": zone.BrigadeID.String(),
		"name":       zone.Name,
		"priority":   zone.Priority,
		"active":     zone.Active,
		"updated_at": zone.UpdatedAt,
	}
	if err = insertOutboxEvent(ctx, tx, "brigade", zone.BrigadeID, "BrigadeZoneUpdated", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: UpdateBrigadeZone: insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repo: UpdateBrigadeZone: commit tx: %w", err)
	}

	return &models.UpdateBrigadeZoneResult{Zone: zone}, nil
}

func (z *ZoneRepoStruct) DeleteBrigadeZone(ctx context.Context, in *models.DeleteBrigadeZoneInput) (*models.DeleteBrigadeZoneResult, error) {
	tx, err := z.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repo: DeleteBrigadeZone: begin tx: %w", err)
	}
	defer tx.Rollback()

	const query = `
		UPDATE brigade_zones
		SET active = false, updated_at = now()
		WHERE id = $1
		RETURNING
			id,
			brigade_id,
			department_id,
			name,
			ST_AsGeoJSON(zone::geometry),
			priority,
			active,
			created_at,
			updated_at
	`
	zone, err := scanBrigadeZone(tx.QueryRowContext(ctx, query, in.ID))
	if err != nil {
		return nil, fmt.Errorf("repo: DeleteBrigadeZone: scan zone: %w", err)
	}

	payload := map[string]any{
		"event_id":   uuid.NewString(),
		"event_type": "BrigadeZoneDeleted",
		"zone_id":    zone.ID.String(),
		"brigade_id": zone.BrigadeID.String(),
		"updated_at": zone.UpdatedAt,
	}
	if err = insertOutboxEvent(ctx, tx, "brigade", zone.BrigadeID, "BrigadeZoneDeleted", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: DeleteBrigadeZone: insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repo: DeleteBrigadeZone: commit tx: %w", err)
	}

	return &models.DeleteBrigadeZoneResult{Zone: zone}, nil
}

func (z *ZoneRepoStruct) ListBrigadeZones(ctx context.Context, in *models.ListBrigadeZonesInput) (*models.ListBrigadeZonesResult, error) {
	whereParts := []string{"brigade_id = $1"}
	args := []any{in.BrigadeID}
	if in.Active != nil {
		args = append(args, *in.Active)
		whereParts = append(whereParts, fmt.Sprintf("active = $%d", len(args)))
	}
	whereSQL := "WHERE " + strings.Join(whereParts, " AND ")

	query := fmt.Sprintf(`
		SELECT
			id,
			brigade_id,
			department_id,
			name,
			ST_AsGeoJSON(zone::geometry),
			priority,
			active,
			created_at,
			updated_at
		FROM brigade_zones
		%s
		ORDER BY priority DESC, created_at DESC
	`, whereSQL)

	rows, err := z.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("repo: ListBrigadeZones: query: %w", err)
	}
	defer rows.Close()

	zones := make([]*models.BrigadeZone, 0)
	for rows.Next() {
		zone, err := scanBrigadeZone(rows)
		if err != nil {
			return nil, fmt.Errorf("repo: ListBrigadeZones: scan: %w", err)
		}
		zones = append(zones, zone)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("repo: ListBrigadeZones: rows: %w", err)
	}
	return &models.ListBrigadeZonesResult{Zones: zones}, nil
}

func (z *ZoneRepoStruct) CheckBrigadeCoversPoint(ctx context.Context, in *models.CheckBrigadeCoversPointInput) (*models.CheckBrigadeCoversPointResult, error) {
	const query = `
		SELECT
			id,
			brigade_id,
			department_id,
			name,
			ST_AsGeoJSON(zone::geometry),
			priority,
			active,
			created_at,
			updated_at
		FROM brigade_zones
		WHERE brigade_id = $1
		  AND active = true
		  AND ST_Covers(zone, ST_SetSRID(ST_MakePoint($2, $3), 4326)::geography)
		ORDER BY priority DESC
	`

	rows, err := z.db.QueryContext(ctx, query, in.BrigadeID, in.Longitude, in.Latitude)
	if err != nil {
		return nil, fmt.Errorf("repo: CheckBrigadeCoversPoint: query: %w", err)
	}
	defer rows.Close()

	zones := make([]*models.BrigadeZone, 0)
	for rows.Next() {
		zone, err := scanBrigadeZone(rows)
		if err != nil {
			return nil, fmt.Errorf("repo: CheckBrigadeCoversPoint: scan: %w", err)
		}
		zones = append(zones, zone)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("repo: CheckBrigadeCoversPoint: rows: %w", err)
	}
	return &models.CheckBrigadeCoversPointResult{Covers: len(zones) > 0, MatchedZones: zones}, nil
}

func (z *ZoneRepoStruct) FindBrigadesByPoint(ctx context.Context, in *models.FindBrigadesByPointInput) (*models.FindBrigadesByPointResult, error) {
	whereParts := []string{
		"b.department_id = $1",
		"bz.active = true",
		"ST_Covers(bz.zone, ST_SetSRID(ST_MakePoint($2, $3), 4326)::geography)",
	}
	args := []any{in.DepartmentID, in.Longitude, in.Latitude}

	if in.OnlyAvailable {
		whereParts = append(whereParts, fmt.Sprintf("b.status = $%d", len(args)+1))
		args = append(args, string(models.BrigadeStatusAvailable))
		whereParts = append(whereParts, brigadeHasActiveMembersSQL("b.id"))
		whereParts = append(whereParts, brigadeHasAvailableActiveMembersSQL("b.id"))
		whereParts = append(whereParts, brigadeIsOnShiftSQL("b.id"))
	}
	if len(in.RequiredSkillIDs) > 0 {
		whereParts = append(whereParts, fmt.Sprintf(`
			(
				SELECT COUNT(DISTINCT bs.skill_id)
				FROM brigade_skills bs
				WHERE bs.brigade_id = b.id
				  AND bs.active = true
				  AND bs.skill_id = ANY($%d)
			) = %d
		`, len(args)+1, len(in.RequiredSkillIDs)))
		args = append(args, pq.Array(uuidStrings(in.RequiredSkillIDs)))
	}
	if len(in.RequiredRoles) > 0 {
		whereParts = append(whereParts, fmt.Sprintf(`
			(
				SELECT COUNT(DISTINCT bm.role)
				FROM brigade_members bm
				WHERE bm.brigade_id = b.id
				  AND bm.active = true
				  AND bm.role = ANY($%d)
			) = %d
		`, len(args)+1, len(in.RequiredRoles)))
		args = append(args, pq.Array(roleStrings(in.RequiredRoles)))
	}
	whereSQL := "WHERE " + strings.Join(whereParts, " AND ")

	countQuery := fmt.Sprintf(`
		SELECT COUNT(DISTINCT b.id)
		FROM brigades b
		JOIN brigade_zones bz ON bz.brigade_id = b.id
		%s
	`, whereSQL)
	var total int64
	if err := z.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("repo: FindBrigadesByPoint: count: %w", err)
	}

	args = append(args, in.Limit, in.Offset)
	query := fmt.Sprintf(`
		SELECT DISTINCT
			b.id,
			b.department_id,
			b.name,
			b.description,
			b.status,
			b.specialization,
			b.created_at,
			b.updated_at,
			b.deactivated_at,
			b.archived_at
		FROM brigades b
		JOIN brigade_zones bz ON bz.brigade_id = b.id
		%s
		ORDER BY b.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereSQL, len(args)-1, len(args))

	rows, err := z.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("repo: FindBrigadesByPoint: query: %w", err)
	}
	defer rows.Close()

	brigades := make([]*models.Brigade, 0)
	for rows.Next() {
		brigade, err := scanBrigade(rows)
		if err != nil {
			return nil, fmt.Errorf("repo: FindBrigadesByPoint: scan: %w", err)
		}
		brigades = append(brigades, brigade)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("repo: FindBrigadesByPoint: rows: %w", err)
	}
	return &models.FindBrigadesByPointResult{Brigades: brigades, Total: total}, nil
}

func (z *ZoneRepoStruct) listAvailableBrigades(ctx context.Context, departmentID uuid.UUID, requiredSkillIDs []uuid.UUID, requiredRoles []models.BrigadeMemberRole, limit int32, offset int32) (*models.GetAvailableBrigadesResult, error) {
	whereParts := []string{"department_id = $1", "status = $2", brigadeHasActiveMembersSQL("brigades.id"), brigadeHasAvailableActiveMembersSQL("brigades.id"), brigadeIsOnShiftSQL("brigades.id")}
	args := []any{departmentID, string(models.BrigadeStatusAvailable)}
	if len(requiredSkillIDs) > 0 {
		whereParts = append(whereParts, fmt.Sprintf(`
			(
				SELECT COUNT(DISTINCT bs.skill_id)
				FROM brigade_skills bs
				WHERE bs.brigade_id = brigades.id
				  AND bs.active = true
				  AND bs.skill_id = ANY($%d)
			) = %d
		`, len(args)+1, len(requiredSkillIDs)))
		args = append(args, pq.Array(uuidStrings(requiredSkillIDs)))
	}
	if len(requiredRoles) > 0 {
		whereParts = append(whereParts, fmt.Sprintf(`
			(
				SELECT COUNT(DISTINCT bm.role)
				FROM brigade_members bm
				WHERE bm.brigade_id = brigades.id
				  AND bm.active = true
				  AND bm.role = ANY($%d)
			) = %d
		`, len(args)+1, len(requiredRoles)))
		args = append(args, pq.Array(roleStrings(requiredRoles)))
	}
	whereSQL := "WHERE " + strings.Join(whereParts, " AND ")

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM brigades %s", whereSQL)
	var total int64
	if err := z.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count: %w", err)
	}

	args = append(args, limit, offset)
	query := fmt.Sprintf(`
		SELECT id, department_id, name, description, status, specialization, created_at, updated_at, deactivated_at, archived_at
		FROM brigades
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereSQL, len(args)-1, len(args))

	rows, err := z.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	brigades := make([]*models.Brigade, 0)
	for rows.Next() {
		brigade, err := scanBrigade(rows)
		if err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		brigades = append(brigades, brigade)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return &models.GetAvailableBrigadesResult{Brigades: brigades, Total: total}, nil
}

func brigadeHasActiveMembersSQL(brigadeIDExpr string) string {
	return fmt.Sprintf(`EXISTS (
		SELECT 1
		FROM brigade_members bm
		WHERE bm.brigade_id = %s
		  AND bm.active = true
	)`, brigadeIDExpr)
}

func brigadeHasAvailableActiveMembersSQL(brigadeIDExpr string) string {
	return fmt.Sprintf(`EXISTS (
		SELECT 1
		FROM brigade_members bm
		WHERE bm.brigade_id = %s
		  AND bm.active = true
		  AND bm.availability_status = 'AVAILABLE'
	)`, brigadeIDExpr)
}

func brigadeIsOnShiftSQL(brigadeIDExpr string) string {
	return fmt.Sprintf(`EXISTS (
		SELECT 1
		FROM brigade_schedule sch
		WHERE sch.brigade_id = %s
		  AND sch.active = true
		  AND (sch.valid_from IS NULL OR (now() AT TIME ZONE sch.timezone)::date >= sch.valid_from)
		  AND (sch.valid_to IS NULL OR (now() AT TIME ZONE sch.timezone)::date <= sch.valid_to)
		  AND EXTRACT(ISODOW FROM now() AT TIME ZONE sch.timezone)::int = sch.day_of_week
		  AND (
			(sch.starts_at < sch.ends_at AND (now() AT TIME ZONE sch.timezone)::time >= sch.starts_at AND (now() AT TIME ZONE sch.timezone)::time < sch.ends_at)
			OR
			(sch.starts_at > sch.ends_at AND ((now() AT TIME ZONE sch.timezone)::time >= sch.starts_at OR (now() AT TIME ZONE sch.timezone)::time < sch.ends_at))
		  )
	)`, brigadeIDExpr)
}

func scanBrigadeZone(row scanner) (*models.BrigadeZone, error) {
	var zone models.BrigadeZone
	err := row.Scan(&zone.ID, &zone.BrigadeID, &zone.DepartmentID, &zone.Name, &zone.GeoJSON, &zone.Priority, &zone.Active, &zone.CreatedAt, &zone.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, models.ErrNotFound
		}
		return nil, err
	}
	return &zone, nil
}
