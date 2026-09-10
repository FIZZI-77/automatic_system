package repository

import (
	"asset/models"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"time"
)

func (r *AssetRepoStruct) CreatePlan(c context.Context, v models.Plan) (*models.Plan, error) {
	e := r.db.QueryRow(c, `INSERT INTO maintenance_plans(asset_id,kind,interval_days,next_due_at)VALUES($1,$2,$3,$4)ON CONFLICT(asset_id,kind)DO UPDATE SET interval_days=$3,next_due_at=$4,active=true RETURNING id,active,last_completed_at`, v.AssetID, v.Kind, v.IntervalDays, v.NextDueAt).Scan(&v.ID, &v.Active, &v.LastCompletedAt)
	return &v, e
}
func (r *AssetRepoStruct) DuePlans(c context.Context, d *uuid.UUID, due time.Time, limit, offset int32) ([]*models.Plan, int64, error) {
	var total int64
	e := r.db.QueryRow(c, `SELECT count(*) FROM maintenance_plans p JOIN assets a ON a.id=p.asset_id WHERE p.active AND p.next_due_at<=$1 AND($2::uuid IS NULL OR a.department_id=$2)`, due, d).Scan(&total)
	if e != nil {
		return nil, 0, e
	}
	rows, e := r.db.Query(c, `SELECT p.id,p.asset_id,p.kind,p.interval_days,p.next_due_at,p.active,p.last_completed_at FROM maintenance_plans p JOIN assets a ON a.id=p.asset_id WHERE p.active AND p.next_due_at<=$1 AND($2::uuid IS NULL OR a.department_id=$2)ORDER BY p.next_due_at LIMIT $3 OFFSET $4`, due, d, limit, offset)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	out := []*models.Plan{}
	for rows.Next() {
		var x models.Plan
		if e = rows.Scan(&x.ID, &x.AssetID, &x.Kind, &x.IntervalDays, &x.NextDueAt, &x.Active, &x.LastCompletedAt); e != nil {
			return nil, 0, e
		}
		out = append(out, &x)
	}
	return out, total, rows.Err()
}
func (r *AssetRepoStruct) RiskFacts(c context.Context, id uuid.UUID, now time.Time) (RiskFacts, error) {
	var f RiskFacts
	var repair, inspection *time.Time
	from90, from365 := now.AddDate(0, 0, -90), now.AddDate(-1, 0, 0)
	e := r.db.QueryRow(c, `SELECT a.installation_year,a.service_life_years,a.criticality,a.last_repair_at,a.next_inspection_at,(SELECT count(*) FROM asset_incidents WHERE asset_id=a.id AND occurred_at>$2),(SELECT count(*) FROM asset_incidents WHERE asset_id=a.id AND occurred_at>$3),(SELECT count(*) FROM asset_incidents WHERE asset_id=a.id AND repeated AND occurred_at>$2),(SELECT count(*) FROM asset_incidents WHERE asset_id=a.id AND priority IN('HIGH','EMERGENCY')AND occurred_at>$2),(SELECT condition_score FROM asset_inspections WHERE asset_id=a.id ORDER BY inspected_at DESC LIMIT 1)FROM assets a WHERE id=$1`, id, from90, from365).Scan(&f.InstallationYear, &f.ServiceLifeYears, &f.Criticality, &repair, &inspection, &f.Incidents90, &f.Incidents365, &f.Repeat90, &f.SLAIncidents90, &f.LastCondition)
	if repair != nil {
		f.DaysSinceRepair = int(now.Sub(*repair).Hours() / 24)
	}
	if inspection != nil && inspection.Before(now) {
		f.DaysInspectionOverdue = int(now.Sub(*inspection).Hours() / 24)
	}
	return f, e
}
func (r *AssetRepoStruct) SavePrediction(c context.Context, p models.Prediction) error {
	raw, _ := json.Marshal(p.Factors)
	tx, e := r.db.Begin(c)
	if e != nil {
		return e
	}
	defer tx.Rollback(c)
	_, e = tx.Exec(c, `INSERT INTO failure_predictions(asset_id,risk_score,risk_level,failure_probability_90d,factors,recommended_action,calculated_at)VALUES($1,$2,$3,$4,$5,$6,$7)`, p.AssetID, p.Score, p.Level, p.Probability, raw, p.Action, p.CalculatedAt)
	if e == nil {
		_, e = tx.Exec(c, "UPDATE assets SET risk_score=$2,risk_level=$3,updated_at=now()WHERE id=$1", p.AssetID, p.Score, p.Level)
	}
	if e == nil {
		e = emit(c, tx, p.AssetID, "asset.RISK_UPDATED", p)
	}
	if e == nil {
		e = tx.Commit(c)
	}
	return e
}
func (r *AssetRepoStruct) GetPrediction(c context.Context, id uuid.UUID) (*models.Prediction, error) {
	var p models.Prediction
	var raw []byte
	e := r.db.QueryRow(c, `SELECT asset_id,risk_score,risk_level,failure_probability_90d,factors,recommended_action,calculated_at FROM failure_predictions WHERE asset_id=$1 ORDER BY calculated_at DESC LIMIT 1`, id).Scan(&p.AssetID, &p.Score, &p.Level, &p.Probability, &raw, &p.Action, &p.CalculatedAt)
	if e == nil {
		e = json.Unmarshal(raw, &p.Factors)
	}
	return &p, e
}
func (r *AssetRepoStruct) ListIDs(c context.Context, d *uuid.UUID) ([]uuid.UUID, error) {
	rows, e := r.db.Query(c, "SELECT id FROM assets WHERE($1::uuid IS NULL OR department_id=$1)", d)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
