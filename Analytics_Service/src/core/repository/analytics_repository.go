package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"analytics/models"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type AnalyticsRepoStruct struct{ db driver.Conn }

func NewAnalyticsRepoStruct(db driver.Conn) *AnalyticsRepoStruct {
	return &AnalyticsRepoStruct{db: db}
}
func (r *AnalyticsRepoStruct) Store(ctx context.Context, event models.Event) error {
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	occurred := eventTime(event)
	entityID := stringValue(event.Payload, "entity_id", "aggregate_id", "ticket_id", "department_id", "brigade_id", "id")
	return r.db.Exec(ctx, `INSERT INTO domain_events(topic,event_id,event_type,entity_id,ticket_id,department_id,category_id,brigade_id,user_id,priority,status,latitude,longitude,payload,occurred_at,version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, event.Topic, event.ID, event.Type, entityID, stringValue(event.Payload, "ticket_id", "id"), stringValue(event.Payload, "department_id"), stringValue(event.Payload, "category_id"), stringValue(event.Payload, "brigade_id"), stringValue(event.Payload, "user_id"), strings.ToUpper(stringValue(event.Payload, "priority")), strings.ToUpper(stringValue(event.Payload, "status", "new_status")), numberValue(event.Payload, "latitude"), numberValue(event.Payload, "longitude"), string(payload), occurred, uint64(occurred.UnixNano()))
}

func (r *AnalyticsRepoStruct) Overview(ctx context.Context, f models.Filter) (models.Overview, error) {
	where, args := buildFilter(f, "occurred_at")
	query := `WITH events AS (SELECT * FROM domain_events FINAL WHERE topic='tickets.events.v1' AND ` + where + `), tickets AS (SELECT ticket_id,minIf(occurred_at,event_type='ticket.created') created_at,minIf(occurred_at,event_type IN ('ticket.assigned','ticket.status_changed') AND status IN ('ASSIGNED','IN_PROGRESS')) response_at,minIf(occurred_at,event_type='ticket.completed') completed_at,argMax(status,occurred_at) current_status FROM events WHERE ticket_id!='' GROUP BY ticket_id) SELECT countIf(created_at>toDateTime64(0,3)),countIf(completed_at>toDateTime64(0,3)),countIf(current_status='CANCELED'),countIf(current_status NOT IN ('DONE','CANCELED')),if(count()=0,0,countIf(completed_at>toDateTime64(0,3))/count()*100),ifNotFinite(avgIf(dateDiff('second',created_at,response_at),response_at>created_at),0),ifNotFinite(avgIf(dateDiff('second',created_at,completed_at),completed_at>created_at),0) FROM tickets`
	var v models.Overview
	err := r.db.QueryRow(ctx, query, args...).Scan(&v.Created, &v.Completed, &v.Canceled, &v.Active, &v.CompletionRate, &v.AvgResponseSeconds, &v.AvgResolutionSeconds)
	return v, err
}

func (r *AnalyticsRepoStruct) SLA(ctx context.Context, f models.Filter) (models.SLA, error) {
	where, args := buildFilter(f, "occurred_at")
	query := `SELECT countIf(event_type LIKE '%RESPONSE_WARNING%'),countIf(event_type LIKE '%RESPONSE_BREACHED%'),countIf(event_type LIKE '%RESOLUTION_WARNING%'),countIf(event_type LIKE '%RESOLUTION_BREACHED%'),countIf(event_type LIKE '%COMPLETED%'),if(count()=0,0,(countIf(event_type LIKE '%RESPONSE_BREACHED%')+countIf(event_type LIKE '%RESOLUTION_BREACHED%'))/count()*100) FROM domain_events FINAL WHERE topic='sla.events.v1' AND ` + where
	var v models.SLA
	err := r.db.QueryRow(ctx, query, args...).Scan(&v.ResponseWarnings, &v.ResponseBreaches, &v.ResolutionWarnings, &v.ResolutionBreaches, &v.Completed, &v.BreachRate)
	return v, err
}

func (r *AnalyticsRepoStruct) Breakdown(ctx context.Context, f models.Filter, dimension string, limit int32) ([]models.Breakdown, uint64, error) {
	column, ok := map[string]string{"DEPARTMENT": "department_id", "CATEGORY": "category_id", "PRIORITY": "priority", "STATUS": "status"}[dimension]
	if !ok {
		return nil, 0, fmt.Errorf("invalid dimension")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	where, args := buildFilter(f, "occurred_at")
	query := `WITH source AS (SELECT ` + column + ` key FROM domain_events FINAL WHERE topic='tickets.events.v1' AND event_type='ticket.created' AND ` + where + `), totals AS (SELECT count() total FROM source) SELECT key,count() count,if(total=0,0,count/total*100),total FROM source CROSS JOIN totals WHERE key!='' GROUP BY key,total ORDER BY count DESC LIMIT ?`
	rows, err := r.db.Query(ctx, query, append(args, limit)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]models.Breakdown, 0)
	var total uint64
	for rows.Next() {
		var v models.Breakdown
		if err = rows.Scan(&v.Key, &v.Count, &v.Percent, &total); err != nil {
			return nil, 0, err
		}
		items = append(items, v)
	}
	return items, total, rows.Err()
}

func (r *AnalyticsRepoStruct) Daily(ctx context.Context, f models.Filter) ([]models.Daily, error) {
	where, args := buildFilter(f, "occurred_at")
	query := `SELECT toStartOfDay(occurred_at) day,countIf(topic='tickets.events.v1' AND event_type='ticket.created'),countIf(topic='tickets.events.v1' AND event_type='ticket.completed'),countIf(topic='tickets.events.v1' AND event_type='ticket.canceled'),countIf(topic='sla.events.v1' AND event_type LIKE '%BREACHED%') FROM domain_events FINAL WHERE ` + where + ` GROUP BY day ORDER BY day`
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]models.Daily, 0)
	for rows.Next() {
		var v models.Daily
		if err = rows.Scan(&v.Day, &v.Created, &v.Completed, &v.Canceled, &v.SLABreaches); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

func eventTime(event models.Event) time.Time {
	occurred := event.Timestamp
	// Entity timestamps such as created_at and updated_at describe the ticket,
	// not the domain event. Using them made assignment and completion appear at
	// the ticket creation time and forced response metrics to zero.
	if raw := stringValue(event.Payload, "occurred_at"); raw != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			occurred = parsed
		}
	}
	if occurred.IsZero() {
		return time.Now().UTC()
	}
	return occurred
}
func (r *AnalyticsRepoStruct) AssetSummary(ctx context.Context, f models.Filter, assetType, district *string) (models.AssetSummary, error) {
	where, args := buildFilter(f, "occurred_at")
	where += " AND topic='assets.events.v1'"
	var v models.AssetSummary
	e := r.db.QueryRow(ctx, `SELECT countIf(event_type='asset.CREATED'),countIf(event_type='asset.INCIDENT_RECORDED'),countIf(event_type='asset.INCIDENT_RECORDED' AND JSONExtractBool(payload,'data','Repeated')),countIf(event_type='asset.REPAIR_COMPLETED'),countIf(event_type='asset.INSPECTION_RECORDED'),countIf(event_type='asset.RISK_UPDATED' AND JSONExtractString(payload,'data','Level')='CRITICAL') FROM domain_events FINAL WHERE `+where, args...).Scan(&v.Created, &v.Incidents, &v.Repeated, &v.Repairs, &v.Inspections, &v.Critical)
	if e != nil {
		return v, e
	}
	v.ByType, e = r.assetGroups(ctx, where, args, "JSONExtractString(payload,'data','Type')", assetType)
	if e == nil {
		v.ByDistrict, e = r.assetGroups(ctx, where, args, "JSONExtractString(payload,'data','District')", district)
	}
	return v, e
}
func (r *AnalyticsRepoStruct) assetGroups(ctx context.Context, where string, args []any, column string, filter *string) ([]models.AssetBreakdown, error) {
	if filter != nil {
		where += " AND " + column + "=?"
		args = append(args, *filter)
	}
	rows, e := r.db.Query(ctx, `SELECT `+column+` key,countIf(event_type='asset.INCIDENT_RECORDED') incidents,countIf(event_type='asset.INCIDENT_RECORDED' AND JSONExtractBool(payload,'data','Repeated')),countIf(event_type='asset.REPAIR_COMPLETED'),countIf(event_type='asset.RISK_UPDATED' AND JSONExtractString(payload,'data','Level')='CRITICAL') FROM domain_events FINAL WHERE `+where+` GROUP BY key HAVING key!='' ORDER BY incidents DESC LIMIT 50`, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []models.AssetBreakdown{}
	for rows.Next() {
		var x models.AssetBreakdown
		if e = rows.Scan(&x.Key, &x.Incidents, &x.Repeated, &x.Repairs, &x.Critical); e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
