package repository

import (
	"asset/models"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"time"
)

type AssetRepoStruct struct{ db *pgxpool.Pool }

func NewAssetRepoStruct(db *pgxpool.Pool) *AssetRepoStruct {
	return &AssetRepoStruct{db: db}
}

const cols = `id,external_id,department_id,type,name,address,district,municipality,ST_AsGeoJSON(geometry),status,model,serial_number,installation_year,service_life_years,warranty_until,owner,service_organization,contractor,inspection_interval_days,response_norm_minutes,repair_norm_minutes,criticality,risk_score,risk_level,last_repair_at,next_inspection_at,created_at,updated_at`

func scan(r pgx.Row) (*models.Asset, error) {
	var x models.Asset
	e := r.Scan(&x.ID, &x.ExternalID, &x.DepartmentID, &x.Type, &x.Name, &x.Address, &x.District, &x.Municipality, &x.Geometry, &x.Status, &x.Model, &x.SerialNumber, &x.InstallationYear, &x.ServiceLifeYears, &x.WarrantyUntil, &x.Owner, &x.ServiceOrganization, &x.Contractor, &x.InspectionIntervalDays, &x.ResponseNormMinutes, &x.RepairNormMinutes, &x.Criticality, &x.RiskScore, &x.RiskLevel, &x.LastRepairAt, &x.NextInspectionAt, &x.CreatedAt, &x.UpdatedAt)
	return &x, e
}
func (r *AssetRepoStruct) Create(c context.Context, v models.CreateInput) (*models.Asset, error) {
	tx, e := r.db.Begin(c)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(c)
	x, e := scan(tx.QueryRow(c, `INSERT INTO assets(external_id,department_id,type,name,address,district,municipality,geometry,model,serial_number,installation_year,service_life_years,warranty_until,owner,service_organization,contractor,inspection_interval_days,response_norm_minutes,repair_norm_minutes,criticality,next_inspection_at)VALUES($1,$2,$3,$4,$5,$6,$7,ST_SetSRID(ST_GeomFromGeoJSON($8),4326),$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,now()+make_interval(days=>$17))RETURNING `+cols, v.ExternalID, v.DepartmentID, v.Type, v.Name, v.Address, v.District, v.Municipality, v.Geometry, v.Model, v.SerialNumber, v.InstallationYear, v.ServiceLifeYears, v.WarrantyUntil, v.Owner, v.ServiceOrganization, v.Contractor, v.InspectionIntervalDays, v.ResponseNormMinutes, v.RepairNormMinutes, v.Criticality))
	if e == nil {
		e = emit(c, tx, x.ID, "asset.CREATED", x)
	}
	if e == nil {
		e = tx.Commit(c)
	}
	return x, e
}
func (r *AssetRepoStruct) Get(c context.Context, id uuid.UUID) (*models.Asset, error) {
	return scan(r.db.QueryRow(c, `SELECT `+cols+` FROM assets WHERE id=$1`, id))
}
func (r *AssetRepoStruct) Update(c context.Context, v models.UpdateInput) (*models.Asset, error) {
	tx, e := r.db.Begin(c)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(c)
	x, e := scan(tx.QueryRow(c, `UPDATE assets SET
		name=COALESCE($2,name),address=COALESCE($3,address),
		geometry=CASE WHEN $4::text IS NULL THEN geometry ELSE ST_SetSRID(ST_GeomFromGeoJSON($4),4326) END,
		contractor=COALESCE($5,contractor),criticality=COALESCE($6,criticality),updated_at=now()
		WHERE id=$1 RETURNING `+cols, v.ID, v.Name, v.Address, v.Geometry, v.Contractor, v.Criticality))
	if e == nil {
		e = emit(c, tx, v.ID, "asset.UPDATED", x)
	}
	if e == nil {
		e = tx.Commit(c)
	}
	return x, e
}
func (r *AssetRepoStruct) List(c context.Context, f models.Filter) ([]*models.Asset, int64, error) {
	w := []string{"true"}
	a := []any{}
	add := func(col string, v any) { a = append(a, v); w = append(w, fmt.Sprintf("%s=$%d", col, len(a))) }
	if f.DepartmentID != nil {
		add("department_id", *f.DepartmentID)
	}
	if f.Type != nil {
		add("type", *f.Type)
	}
	if f.District != nil {
		add("district", *f.District)
	}
	if f.Status != nil {
		add("status", *f.Status)
	}
	if f.RiskLevel != nil {
		add("risk_level", *f.RiskLevel)
	}
	q := strings.Join(w, " AND ")
	var total int64
	if e := r.db.QueryRow(c, "SELECT count(*) FROM assets WHERE "+q, a...).Scan(&total); e != nil {
		return nil, 0, e
	}
	a = append(a, f.Limit, f.Offset)
	rows, e := r.db.Query(c, "SELECT "+cols+" FROM assets WHERE "+q+fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(a)-1, len(a)), a...)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	out := []*models.Asset{}
	for rows.Next() {
		x, e := scan(rows)
		if e != nil {
			return nil, 0, e
		}
		out = append(out, x)
	}
	return out, total, rows.Err()
}
func (r *AssetRepoStruct) ChangeStatus(c context.Context, id uuid.UUID, s models.Status, actor uuid.UUID, reason string) (*models.Asset, error) {
	tx, e := r.db.Begin(c)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(c)
	var old models.Status
	e = tx.QueryRow(c, "SELECT status FROM assets WHERE id=$1 FOR UPDATE", id).Scan(&old)
	if e != nil {
		return nil, e
	}
	x, e := scan(tx.QueryRow(c, "UPDATE assets SET status=$2,updated_at=now() WHERE id=$1 RETURNING "+cols, id, s))
	if e == nil {
		_, e = tx.Exec(c, "INSERT INTO asset_status_history(asset_id,old_status,new_status,reason,changed_by)VALUES($1,$2,$3,$4,$5)", id, old, s, reason, actor)
	}
	if e == nil {
		e = emit(c, tx, id, "asset.STATUS_CHANGED", map[string]any{"asset_id": id, "old_status": old, "status": s})
	}
	if e == nil {
		e = tx.Commit(c)
	}
	return x, e
}
func (r *AssetRepoStruct) Nearby(c context.Context, lat, lon, radius float64, t *string, limit int32) ([]*models.Asset, error) {
	rows, e := r.db.Query(c, "SELECT "+cols+` FROM assets WHERE($4::text IS NULL OR type=$4)AND ST_DWithin(geometry::geography,ST_SetSRID(ST_Point($2,$1),4326)::geography,$3)ORDER BY ST_Distance(geometry::geography,ST_SetSRID(ST_Point($2,$1),4326)::geography)LIMIT $5`, lat, lon, radius, t, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []*models.Asset
	for rows.Next() {
		x, e := scan(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (r *AssetRepoStruct) RecordIncident(c context.Context, v models.Incident) (*models.Incident, error) {
	tx, e := r.db.Begin(c)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(c)
	e = tx.QueryRow(c, "SELECT EXISTS(SELECT 1 FROM asset_incidents WHERE asset_id=$1 AND failure_type=$2 AND occurred_at>$3)", v.AssetID, v.FailureType, v.OccurredAt.AddDate(0, 0, -90)).Scan(&v.Repeated)
	if e == nil {
		e = tx.QueryRow(c, `INSERT INTO asset_incidents(asset_id,ticket_id,failure_type,description,source,priority,repeated,occurred_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8)RETURNING id`, v.AssetID, v.TicketID, v.FailureType, v.Description, v.Source, v.Priority, v.Repeated, v.OccurredAt).Scan(&v.ID)
	}
	if e == nil {
		_, e = tx.Exec(c, "UPDATE assets SET status='DAMAGED',updated_at=now()WHERE id=$1", v.AssetID)
	}
	if e == nil {
		e = emit(c, tx, v.AssetID, "asset.INCIDENT_RECORDED", v)
	}
	if e == nil {
		e = tx.Commit(c)
	}
	return &v, e
}
func (r *AssetRepoStruct) CompleteRepair(c context.Context, v models.Repair) (*models.Repair, error) {
	tx, e := r.db.Begin(c)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(c)
	e = tx.QueryRow(c, `INSERT INTO asset_repairs(asset_id,incident_id,ticket_id,brigade_id,description,replaced_components,duration_minutes,completed_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8)RETURNING id`, v.AssetID, v.IncidentID, v.TicketID, v.BrigadeID, v.Description, v.ReplacedComponents, v.DurationMinutes, v.CompletedAt).Scan(&v.ID)
	if e == nil {
		_, e = tx.Exec(c, "UPDATE assets SET status='ACTIVE',last_repair_at=$2,updated_at=now()WHERE id=$1", v.AssetID, v.CompletedAt)
	}
	if e == nil {
		e = emit(c, tx, v.AssetID, "asset.REPAIR_COMPLETED", v)
	}
	if e == nil {
		e = tx.Commit(c)
	}
	return &v, e
}
func (r *AssetRepoStruct) RecordInspection(c context.Context, v models.Inspection) (*models.Inspection, error) {
	tx, e := r.db.Begin(c)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(c)
	e = tx.QueryRow(c, `INSERT INTO asset_inspections(asset_id,inspector_user_id,kind,result,defect_found,condition_score,recommendation,inspected_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8)RETURNING id`, v.AssetID, v.InspectorID, v.Kind, v.Result, v.DefectFound, v.ConditionScore, v.Recommendation, v.InspectedAt).Scan(&v.ID)
	if e == nil {
		_, e = tx.Exec(c, "UPDATE assets SET next_inspection_at=($2::timestamptz)+make_interval(days=>inspection_interval_days),updated_at=now() WHERE id=$1", v.AssetID, v.InspectedAt)
	}
	if e == nil {
		e = emit(c, tx, v.AssetID, "asset.INSPECTION_RECORDED", v)
	}
	if e == nil {
		e = tx.Commit(c)
	}
	return &v, e
}
func emit(c context.Context, tx pgx.Tx, id uuid.UUID, kind string, v any) error {
	raw, _ := json.Marshal(map[string]any{"event_id": uuid.New(), "event_type": kind, "occurred_at": time.Now().UTC(), "aggregate_id": id, "data": v})
	_, e := tx.Exec(c, "INSERT INTO outbox_events(aggregate_id,event_type,payload)VALUES($1,$2,$3)", id, kind, raw)
	return e
}
