package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
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
	entityID := eventEntityID(event)
	routeID := eventRouteID(event)
	return r.db.Exec(
		ctx,
		`INSERT INTO domain_events(topic,event_id,event_type,entity_id,ticket_id,department_id,category_id,asset_id,brigade_id,shift_id,user_id,member_id,member_status,availability_status,member_role,member_active,route_id,trace_id,priority,status,assignment_mode,failure_code,failure_stage,success,calculation_duration_ms,candidate_count,reachable_candidate_count,engine,travel_mode,latitude,longitude,route_revision,distance_meters,duration_seconds,speed_kmh,accuracy_meters,destination_latitude,destination_longitude,payload,occurred_at,event_version,projection_eligible,version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		event.Topic,
		event.ID,
		event.Type,
		entityID,
		stringValue(event.Payload, "ticket_id", "id"),
		stringValue(event.Payload, "department_id"),
		stringValue(event.Payload, "category_id"),
		stringValue(event.Payload, "asset_id"),
		stringValue(event.Payload, "brigade_id"),
		stringValue(event.Payload, "shift_id"),
		stringValue(event.Payload, "user_id"),
		stringValue(event.Payload, "member_id"),
		strings.ToUpper(stringValue(event.Payload, "member_status")),
		strings.ToUpper(stringValue(event.Payload, "availability_status", "to_status")),
		strings.ToUpper(stringValue(event.Payload, "role", "new_role")),
		boolValue(event.Payload, "active"),
		routeID,
		stringValue(event.Payload, "trace_id"),
		strings.ToUpper(stringValue(event.Payload, "priority")),
		strings.ToUpper(stringValue(event.Payload, "status", "new_status")),
		strings.ToUpper(stringValue(event.Payload, "assignment_mode", "mode")),
		strings.ToUpper(stringValue(event.Payload, "failure_code")),
		strings.ToUpper(stringValue(event.Payload, "failure_stage")),
		boolValue(event.Payload, "success", "calculation_success"),
		numberValue(event.Payload, "calculation_duration_ms"),
		uint64Value(event.Payload, "candidate_count"),
		uint64Value(event.Payload, "reachable_candidate_count"),
		strings.ToLower(stringValue(event.Payload, "engine")),
		strings.ToLower(stringValue(event.Payload, "travel_mode")),
		numberValue(event.Payload, "latitude"),
		numberValue(event.Payload, "longitude"),
		uint64Value(event.Payload, "revision"),
		numberValue(event.Payload, "distance_meters"),
		numberValue(event.Payload, "duration_seconds"),
		numberValue(event.Payload, "speed_kmh"),
		numberValue(event.Payload, "accuracy_meters"),
		numberPathValue(event.Payload, "destination", "latitude"),
		numberPathValue(event.Payload, "destination", "longitude"),
		string(payload),
		occurred,
		event.Version,
		event.ProjectionEligible,
		uint64(occurred.UnixNano()),
	)
}

func eventRouteID(event models.Event) string {
	routeID := stringValue(event.Payload, "route_id")
	if routeID == "" && event.Topic == "routing.events.v1" {
		return stringValue(event.Payload, "id")
	}
	return routeID
}

func eventEntityID(event models.Event) string {
	if value := stringValue(event.Payload, "entity_id", "aggregate_id"); value != "" {
		return value
	}
	switch event.Topic {
	case "dispatch.events.v1":
		return stringValue(event.Payload, "operation_id", "ticket_id", "id")
	case "tickets.events.v1":
		return stringValue(event.Payload, "ticket_id", "id")
	case "brigades.events.v1":
		return stringValue(event.Payload, "brigade_id", "id")
	case "routing.events.v1":
		return eventRouteID(event)
	default:
		return stringValue(event.Payload, "ticket_id", "brigade_id", "department_id", "operation_id", "id")
	}
}

func (r *AnalyticsRepoStruct) DispatchFailures(ctx context.Context, filter models.Filter) (models.DispatchFailureSummary, error) {
	cte, args := dispatchFailureLifecycle(filter)
	query := cte + ` SELECT
		countIf(requested),
		countIf(terminal_status='FAILED'),
		countIf(terminal_status='EXPIRED'),
		countIf(terminal_status IN ('CANCELED','CANCELLED'))
	FROM filtered`
	var result models.DispatchFailureSummary
	if err := r.db.QueryRow(ctx, query, args...).Scan(&result.Requested, &result.Failed, &result.Expired, &result.Canceled); err != nil {
		return models.DispatchFailureSummary{}, err
	}
	unsuccessful := result.Failed + result.Expired + result.Canceled
	if result.Requested > 0 {
		result.FailureRate = float64(unsuccessful) / float64(result.Requested) * 100
	}
	var err error
	result.ByStage, err = r.dispatchFailureBreakdown(ctx, filter, "failure_stage", unsuccessful)
	if err != nil {
		return models.DispatchFailureSummary{}, err
	}
	result.ByCode, err = r.dispatchFailureBreakdown(ctx, filter, "failure_code", unsuccessful)
	if err != nil {
		return models.DispatchFailureSummary{}, err
	}
	result.BusinessReasons, err = r.dispatchBusinessReasons(ctx, filter, result.Requested)
	if err != nil {
		return models.DispatchFailureSummary{}, err
	}
	result.ReasonsByDepartment, err = r.dispatchReasonDimensions(ctx, filter, "department_id")
	if err != nil {
		return models.DispatchFailureSummary{}, err
	}
	result.ReasonsByCategory, err = r.dispatchReasonDimensions(ctx, filter, "category_id")
	if err != nil {
		return models.DispatchFailureSummary{}, err
	}
	return result, nil
}

func (r *AnalyticsRepoStruct) DispatchEffectiveness(ctx context.Context, filter models.Filter) (models.DispatchEffectiveness, error) {
	cte, args := dispatchFailureLifecycle(filter)
	query := cte + ` SELECT
		countIf(requested AND assignment_mode='AUTOMATIC'),
		countIf(terminal_status='ASSIGNED' AND assignment_mode='AUTOMATIC'),
		countIf(requested AND assignment_mode='MANUAL'),
		countIf(terminal_status='ASSIGNED' AND assignment_mode='MANUAL')
	FROM filtered`
	result := models.DispatchEffectiveness{
		Automatic: models.DispatchModeEffectiveness{Mode: "AUTOMATIC"},
		Manual:    models.DispatchModeEffectiveness{Mode: "MANUAL"},
	}
	if err := r.db.QueryRow(ctx, query, args...).Scan(
		&result.Automatic.Requested,
		&result.Automatic.Assigned,
		&result.Manual.Requested,
		&result.Manual.Assigned,
	); err != nil {
		return models.DispatchEffectiveness{}, err
	}
	if result.Automatic.Requested > 0 {
		result.Automatic.SuccessRate = float64(result.Automatic.Assigned) / float64(result.Automatic.Requested) * 100
	}
	if result.Manual.Requested > 0 {
		result.Manual.SuccessRate = float64(result.Manual.Assigned) / float64(result.Manual.Requested) * 100
	}
	automaticMode := "AUTOMATIC"
	automaticFilter := filter
	automaticFilter.AssignmentMode = &automaticMode
	latency, err := r.assignmentLatency(ctx, automaticFilter)
	if err != nil {
		return models.DispatchEffectiveness{}, err
	}
	result.Automatic.AssignmentTime = latency
	manualMode := "MANUAL"
	manualFilter := filter
	manualFilter.AssignmentMode = &manualMode
	latency, err = r.assignmentLatency(ctx, manualFilter)
	if err != nil {
		return models.DispatchEffectiveness{}, err
	}
	result.Manual.AssignmentTime = latency
	return result, nil
}

func (r *AnalyticsRepoStruct) BrigadeWorkload(ctx context.Context, filter models.Filter) (models.BrigadeWorkload, error) {
	periodWhere, args := buildTimeFilter(filter, "occurred_at")
	snapshotWhere := "1=1"
	if filter.To != nil {
		snapshotWhere += " AND occurred_at<=?"
		args = append(args, *filter.To)
	}
	dimensionWhere, dimensionArgs := buildAssignmentDimensions(filter)
	args = append(args, dimensionArgs...)
	query := `WITH events AS (
		SELECT *,(` + periodWhere + `) AS in_period FROM domain_events_projection_v1 FINAL
		WHERE projection_eligible AND topic='tickets.events.v1' AND ` + snapshotWhere + `
	), lifecycle AS (
		SELECT ticket_id,
			argMax(status,occurred_at) AS current_status,
			argMaxIf(department_id,occurred_at,department_id!='') AS department_id,
			argMaxIf(category_id,occurred_at,category_id!='') AS category_id,
			argMaxIf(priority,occurred_at,priority!='') AS priority,
			argMaxIf(brigade_id,occurred_at,brigade_id!='') AS brigade_id,
			argMaxIf(assignment_mode,occurred_at,assignment_mode!='') AS assignment_mode,
			countIf(in_period AND lowerUTF8(event_type)='ticket.created') AS incoming,
			countIf(in_period AND lowerUTF8(event_type)='ticket.assigned') AS assigned,
			countIf(in_period AND lowerUTF8(event_type)='ticket.completed') AS completed
		FROM events WHERE ticket_id!='' GROUP BY ticket_id
	), filtered AS (
		SELECT * FROM lifecycle WHERE ` + dimensionWhere + `
	)
	SELECT brigade_id,sum(incoming),sum(assigned),sum(completed),
		countIf(current_status IN ('ASSIGNED','IN_PROGRESS')),
		countIf(brigade_id='' AND current_status='NEW')
	FROM filtered GROUP BY brigade_id ORDER BY brigade_id`
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return models.BrigadeWorkload{}, err
	}
	defer rows.Close()
	result := models.BrigadeWorkload{Brigades: make([]models.BrigadeWorkloadItem, 0)}
	for rows.Next() {
		var item models.BrigadeWorkloadItem
		var unassigned uint64
		if err = rows.Scan(&item.BrigadeID, &item.Incoming, &item.Assigned, &item.Completed, &item.Active, &unassigned); err != nil {
			return models.BrigadeWorkload{}, err
		}
		result.Incoming += item.Incoming
		result.Assigned += item.Assigned
		result.Completed += item.Completed
		result.Active += item.Active
		result.UnassignedBacklog += unassigned
		if item.BrigadeID != "" {
			result.Brigades = append(result.Brigades, item)
		}
	}
	if err = rows.Err(); err != nil {
		return models.BrigadeWorkload{}, err
	}
	eligibleBrigades, err := r.eligibleBrigadeIDs(ctx, filter)
	if err != nil {
		return models.BrigadeWorkload{}, err
	}
	result.Brigades = mergeEligibleBrigades(result.Brigades, eligibleBrigades)
	applyWorkloadBalance(&result)
	return result, nil
}

func (r *AnalyticsRepoStruct) OperationalInsights(ctx context.Context, filter models.Filter) (models.OperationalInsights, error) {
	departure, err := r.departureTime(ctx, filter)
	if err != nil {
		return models.OperationalInsights{}, err
	}
	queue, err := r.queueAge(ctx, filter)
	if err != nil {
		return models.OperationalInsights{}, err
	}
	routing, err := r.routingEfficiency(ctx, filter)
	if err != nil {
		return models.OperationalInsights{}, err
	}
	capacity, err := r.capacityForecast(ctx, filter)
	if err != nil {
		return models.OperationalInsights{}, err
	}
	return models.OperationalInsights{
		DepartureTime: departure, QueueAge: queue, Routing: routing, CapacityForecast: capacity,
	}, nil
}

func (r *AnalyticsRepoStruct) ProjectionHealth(ctx context.Context) (models.ProjectionHealth, error) {
	const summaryQuery = `SELECT count(),countIf(NOT projection_eligible),
		if(count()=0,0,countIf(projection_eligible)/count()*100),max(occurred_at),max(ingested_at),
		if(count()=0,0,dateDiff('millisecond',max(occurred_at),now64(3))/1000.0),
		ifNotFinite(quantileExact(0.95)(greatest(0,dateDiff('millisecond',occurred_at,ingested_at)/1000.0)),0)
	FROM domain_events FINAL`
	var result models.ProjectionHealth
	if err := r.db.QueryRow(ctx, summaryQuery).Scan(
		&result.TotalEvents, &result.UnknownVersionEvents, &result.ProjectionEligibleRate,
		&result.LastOccurredAt, &result.LastIngestedAt, &result.FreshnessSeconds, &result.IngestionP95Seconds,
	); err != nil {
		return models.ProjectionHealth{}, err
	}
	const topicsQuery = `SELECT topic,count(),countIf(NOT projection_eligible),
		if(count()=0,0,countIf(projection_eligible)/count()*100),max(occurred_at),max(ingested_at),
		dateDiff('millisecond',max(occurred_at),now64(3))/1000.0,
		ifNotFinite(quantileExact(0.95)(greatest(0,dateDiff('millisecond',occurred_at,ingested_at)/1000.0)),0)
	FROM domain_events FINAL GROUP BY topic ORDER BY topic`
	rows, err := r.db.Query(ctx, topicsQuery)
	if err != nil {
		return models.ProjectionHealth{}, err
	}
	defer rows.Close()
	result.Topics = make([]models.ProjectionTopicHealth, 0)
	for rows.Next() {
		var item models.ProjectionTopicHealth
		if err = rows.Scan(
			&item.Topic, &item.TotalEvents, &item.UnknownVersionEvents, &item.ProjectionEligibleRate,
			&item.LastOccurredAt, &item.LastIngestedAt, &item.FreshnessSeconds, &item.IngestionP95Seconds,
		); err != nil {
			return models.ProjectionHealth{}, err
		}
		result.Topics = append(result.Topics, item)
	}
	if err = rows.Err(); err != nil {
		return models.ProjectionHealth{}, err
	}
	const reconciliationQuery = `SELECT
		(SELECT count() FROM domain_events_projection_v1 FINAL),
		greatest(0,toInt64((SELECT count() FROM domain_events FINAL))-toInt64((SELECT count() FROM domain_events_projection_v1 FINAL)))`
	var missingProjectionEvents int64
	if err = r.db.QueryRow(ctx, reconciliationQuery).Scan(&result.ProjectedEvents, &missingProjectionEvents); err != nil {
		return models.ProjectionHealth{}, err
	}
	result.MissingProjectionEvents = uint64(missingProjectionEvents)
	if result.TotalEvents > 0 {
		result.ProjectionErrorRate = float64(result.MissingProjectionEvents) / float64(result.TotalEvents) * 100
	}
	return result, nil
}

func (r *AnalyticsRepoStruct) DispatchOperations(ctx context.Context, filter models.Filter, limit uint32) ([]models.DispatchOperationItem, error) {
	if limit == 0 || limit > 100 {
		limit = 25
	}
	cte, args := dispatchFailureLifecycle(filter)
	args = append(args, limit)
	query := cte + ` SELECT operation_id,ticket_id,department_id,category_id,brigade_id,assignment_mode,
		terminal_status,failure_code,failure_stage,trace_id,requested_at,updated_at
	FROM filtered ORDER BY updated_at DESC LIMIT ?`
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]models.DispatchOperationItem, 0)
	for rows.Next() {
		var item models.DispatchOperationItem
		if err = rows.Scan(
			&item.OperationID, &item.TicketID, &item.DepartmentID, &item.CategoryID, &item.BrigadeID,
			&item.AssignmentMode, &item.Status, &item.FailureCode, &item.FailureStage, &item.TraceID,
			&item.RequestedAt, &item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *AnalyticsRepoStruct) BrigadePerformance(ctx context.Context, filter models.Filter) (models.BrigadePerformance, error) {
	total, err := r.brigadePerformanceGroups(ctx, filter, "'TOTAL'")
	if err != nil {
		return models.BrigadePerformance{}, err
	}
	brigades, err := r.brigadePerformanceGroups(ctx, filter, "brigade_id")
	if err != nil {
		return models.BrigadePerformance{}, err
	}
	shiftTotal, shiftsByBrigade, err := r.brigadeShiftMetrics(ctx, filter)
	if err != nil {
		return models.BrigadePerformance{}, err
	}
	result := models.BrigadePerformance{Brigades: brigades, ShiftMetricsAvailable: shiftTotal.ShiftCount > 0}
	if len(total) == 1 {
		result.Completed = total[0].Completed
		result.ExecutionTime = total[0].ExecutionTime
		result.SLABreaches = total[0].SLABreaches
		result.SLABreachRate = total[0].SLABreachRate
		result.RepeatedAssetTickets = total[0].RepeatedAssetTickets
	}
	applyShiftMetrics(&result, shiftTotal)
	for index := range result.Brigades {
		shift := shiftsByBrigade[result.Brigades[index].BrigadeID]
		applyBrigadeShiftMetrics(&result.Brigades[index], shift)
	}
	return result, nil
}

type brigadeShiftMetric struct {
	ShiftCount uint64
	ShiftHours float64
}

func applyShiftMetrics(result *models.BrigadePerformance, shift brigadeShiftMetric) {
	result.ShiftCount = shift.ShiftCount
	result.ShiftHours = shift.ShiftHours
	if shift.ShiftCount > 0 {
		result.CompletedPerShift = float64(result.Completed) / float64(shift.ShiftCount)
	}
	if shift.ShiftHours > 0 {
		result.BusyHours = result.ExecutionTime.AverageSeconds * float64(result.ExecutionTime.SampleCount) / 3600
		result.AverageParallelTasks = result.BusyHours / shift.ShiftHours
		result.UtilizationRate = math.Min(100, result.AverageParallelTasks*100)
	}
}

func applyBrigadeShiftMetrics(result *models.BrigadePerformanceItem, shift brigadeShiftMetric) {
	result.ShiftCount = shift.ShiftCount
	result.ShiftHours = shift.ShiftHours
	if shift.ShiftCount > 0 {
		result.CompletedPerShift = float64(result.Completed) / float64(shift.ShiftCount)
	}
	if shift.ShiftHours > 0 {
		result.BusyHours = result.ExecutionTime.AverageSeconds * float64(result.ExecutionTime.SampleCount) / 3600
		result.AverageParallelTasks = result.BusyHours / shift.ShiftHours
		result.UtilizationRate = math.Min(100, result.AverageParallelTasks*100)
	}
}

func (r *AnalyticsRepoStruct) brigadeShiftMetrics(ctx context.Context, filter models.Filter) (brigadeShiftMetric, map[string]brigadeShiftMetric, error) {
	parts := []string{"started_at>toDateTime64(0,3)"}
	args := make([]any, 0, 4)
	if filter.From != nil {
		parts = append(parts, "started_at>=?")
		args = append(args, *filter.From)
	}
	if filter.To != nil {
		parts = append(parts, "started_at<=?")
		args = append(args, *filter.To)
	}
	if filter.DepartmentID != nil {
		parts = append(parts, "department_id=?")
		args = append(args, *filter.DepartmentID)
	}
	if filter.BrigadeID != nil {
		parts = append(parts, "brigade_id=?")
		args = append(args, *filter.BrigadeID)
	}
	query := `WITH shifts AS (
		SELECT shift_id,
			argMaxIf(brigade_id,occurred_at,brigade_id!='') brigade_id,
			argMaxIf(department_id,occurred_at,department_id!='') department_id,
			minIf(occurred_at,lowerUTF8(event_type)='brigadeshiftstarted') started_at,
			maxIf(occurred_at,lowerUTF8(event_type)='brigadeshiftended') ended_at
		FROM domain_events_projection_v1 FINAL
		WHERE projection_eligible AND shift_id!='' GROUP BY shift_id
	), filtered AS (
		SELECT brigade_id,
			dateDiff('millisecond',started_at,if(ended_at>started_at,ended_at,least(now64(3),?)))/3600000.0 shift_hours
		FROM shifts WHERE ` + strings.Join(parts, " AND ") + `
	)
	SELECT brigade_id,count(),ifNotFinite(sum(greatest(0,shift_hours)),0)
	FROM filtered GROUP BY brigade_id ORDER BY brigade_id`
	upperBound := time.Now().UTC()
	if filter.To != nil && filter.To.Before(upperBound) {
		upperBound = *filter.To
	}
	queryArgs := append([]any{upperBound}, args...)
	rows, err := r.db.Query(ctx, query, queryArgs...)
	if err != nil {
		return brigadeShiftMetric{}, nil, err
	}
	defer rows.Close()
	byBrigade := make(map[string]brigadeShiftMetric)
	var total brigadeShiftMetric
	for rows.Next() {
		var brigadeID string
		var metric brigadeShiftMetric
		if err = rows.Scan(&brigadeID, &metric.ShiftCount, &metric.ShiftHours); err != nil {
			return brigadeShiftMetric{}, nil, err
		}
		byBrigade[brigadeID] = metric
		total.ShiftCount += metric.ShiftCount
		total.ShiftHours += metric.ShiftHours
	}
	return total, byBrigade, rows.Err()
}

func (r *AnalyticsRepoStruct) brigadePerformanceGroups(ctx context.Context, filter models.Filter, expression string) ([]models.BrigadePerformanceItem, error) {
	if expression != "'TOTAL'" && expression != "brigade_id" {
		return nil, fmt.Errorf("invalid brigade performance expression %q", expression)
	}
	timeWhere, args := buildTimeFilter(filter, "occurred_at")
	dimensionWhere, dimensionArgs := buildAssignmentDimensions(filter)
	args = append(args, dimensionArgs...)
	query := `WITH lifecycle AS (
		SELECT ticket_id,
			minIf(occurred_at,lowerUTF8(event_type)='ticket.created') created_at,
			minIf(occurred_at,lowerUTF8(event_type)='ticket.assigned') assigned_at,
			minIf(occurred_at,lowerUTF8(event_type)='ticket.status_changed' AND status='IN_PROGRESS') started_at,
			minIf(occurred_at,lowerUTF8(event_type)='ticket.completed') completed_at,
			argMaxIf(department_id,occurred_at,department_id!='') department_id,
			argMaxIf(category_id,occurred_at,category_id!='') category_id,
			argMaxIf(asset_id,occurred_at,asset_id!='') asset_id,
			argMaxIf(priority,occurred_at,priority!='') priority,
			argMaxIf(brigade_id,occurred_at,brigade_id!='') brigade_id,
			argMaxIf(assignment_mode,occurred_at,assignment_mode!='') assignment_mode
		FROM domain_events_projection_v1 FINAL
		WHERE projection_eligible AND topic='tickets.events.v1' AND ticket_id!='' AND ` + timeWhere + ` GROUP BY ticket_id
	), filtered AS (
		SELECT *,if(started_at>toDateTime64(0,3),started_at,assigned_at) execution_started_at
		FROM lifecycle WHERE completed_at>toDateTime64(0,3) AND brigade_id!='' AND ` + dimensionWhere + `
	), ranked AS (
		SELECT *,row_number() OVER (PARTITION BY asset_id ORDER BY created_at,ticket_id) asset_sequence FROM filtered
	), sla AS (
		SELECT ticket_id,countIf(positionCaseInsensitive(event_type,'BREACHED')>0) breaches
		FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND topic='sla.events.v1' AND ticket_id!='' GROUP BY ticket_id
	), enriched AS (
		SELECT ranked.*,ifNull(sla.breaches,0) breaches FROM ranked LEFT JOIN sla USING(ticket_id)
	)
	SELECT toString(` + expression + `) key,count(),
		countIf(completed_at>execution_started_at),
		ifNotFinite(avgIf(dateDiff('millisecond',execution_started_at,completed_at)/1000.0,completed_at>execution_started_at),0),
		ifNotFinite(quantileExactIf(0.5)(dateDiff('millisecond',execution_started_at,completed_at)/1000.0,completed_at>execution_started_at),0),
		ifNotFinite(quantileExactIf(0.9)(dateDiff('millisecond',execution_started_at,completed_at)/1000.0,completed_at>execution_started_at),0),
		ifNotFinite(quantileExactIf(0.95)(dateDiff('millisecond',execution_started_at,completed_at)/1000.0,completed_at>execution_started_at),0),
		ifNotFinite(quantileExactIf(0.99)(dateDiff('millisecond',execution_started_at,completed_at)/1000.0,completed_at>execution_started_at),0),
		countIf(breaches>0),countIf(asset_id!='' AND asset_sequence>1)
	FROM enriched GROUP BY ` + expression + ` HAVING key!='' ORDER BY key`
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]models.BrigadePerformanceItem, 0)
	for rows.Next() {
		var item models.BrigadePerformanceItem
		if err = rows.Scan(
			&item.BrigadeID, &item.Completed, &item.ExecutionTime.SampleCount,
			&item.ExecutionTime.AverageSeconds, &item.ExecutionTime.MedianSeconds, &item.ExecutionTime.P90Seconds,
			&item.ExecutionTime.P95Seconds, &item.ExecutionTime.P99Seconds,
			&item.SLABreaches, &item.RepeatedAssetTickets,
		); err != nil {
			return nil, err
		}
		if item.Completed > 0 {
			item.SLABreachRate = float64(item.SLABreaches) / float64(item.Completed) * 100
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *AnalyticsRepoStruct) departureTime(ctx context.Context, filter models.Filter) (models.LatencyDistribution, error) {
	timeWhere, args := buildTimeFilter(filter, "occurred_at")
	dimensionWhere, dimensionArgs := buildAssignmentDimensions(filter)
	args = append(args, dimensionArgs...)
	query := `WITH lifecycle AS (
		SELECT ticket_id,
			minIf(occurred_at,lowerUTF8(event_type)='ticket.assigned') AS assigned_at,
			minIf(occurred_at,lowerUTF8(event_type)='ticket.status_changed' AND status='IN_PROGRESS') AS status_departed_at,
			argMaxIf(department_id,occurred_at,department_id!='') AS department_id,
			argMaxIf(category_id,occurred_at,category_id!='') AS category_id,
			argMaxIf(priority,occurred_at,priority!='') AS priority,
			argMaxIf(brigade_id,occurred_at,brigade_id!='') AS brigade_id,
			argMaxIf(assignment_mode,occurred_at,assignment_mode!='') AS assignment_mode
		FROM domain_events_projection_v1 FINAL
		WHERE projection_eligible AND topic='tickets.events.v1' AND ticket_id!='' AND ` + timeWhere + `
		GROUP BY ticket_id
	), movement AS (
		SELECT ticket.ticket_id,
			minIf(position.occurred_at,position.occurred_at>ticket.assigned_at AND ifNull(position.speed_kmh,0)>=5 AND ifNull(position.accuracy_meters,999999)<=50) AS movement_at
		FROM lifecycle ticket LEFT JOIN (
			SELECT * FROM domain_events_projection_v1 FINAL
			WHERE topic='locations.events.v1' AND lowerUTF8(event_type)='vehiclepositionupdated'
		) position ON position.brigade_id=ticket.brigade_id
		GROUP BY ticket.ticket_id
	), durations AS (
		SELECT dateDiff('millisecond',assigned_at,
			multiIf(status_departed_at>toDateTime64(0,3) AND movement_at>toDateTime64(0,3),least(status_departed_at,movement_at),
				status_departed_at>toDateTime64(0,3),status_departed_at,movement_at))/1000.0 AS seconds
		FROM lifecycle LEFT JOIN movement USING(ticket_id)
		WHERE greatest(status_departed_at,movement_at)>assigned_at AND assigned_at>toDateTime64(0,3) AND ` + dimensionWhere + `
	)
	SELECT count(),ifNotFinite(avg(seconds),0),ifNotFinite(quantileExact(0.5)(seconds),0),
		ifNotFinite(quantileExact(0.9)(seconds),0),ifNotFinite(quantileExact(0.95)(seconds),0),
		ifNotFinite(quantileExact(0.99)(seconds),0) FROM durations`
	return scanLatency(r.db.QueryRow(ctx, query, args...))
}

func (r *AnalyticsRepoStruct) queueAge(ctx context.Context, filter models.Filter) (models.QueueAgeSummary, error) {
	asOf := time.Now().UTC()
	snapshotWhere := "1=1"
	args := []any{asOf}
	if filter.To != nil {
		asOf = *filter.To
		args[0] = asOf
		snapshotWhere += " AND occurred_at<=?"
		args = append(args, *filter.To)
	}
	dimensionWhere, dimensionArgs := buildAssignmentDimensions(filter)
	args = append(args, dimensionArgs...)
	query := `WITH toDateTime64(?,3,'UTC') AS as_of, lifecycle AS (
		SELECT ticket_id,minIf(occurred_at,lowerUTF8(event_type)='ticket.created') AS created_at,
			argMax(status,occurred_at) AS current_status,
			argMaxIf(department_id,occurred_at,department_id!='') AS department_id,
			argMaxIf(category_id,occurred_at,category_id!='') AS category_id,
			argMaxIf(priority,occurred_at,priority!='') AS priority,
			argMaxIf(brigade_id,occurred_at,brigade_id!='') AS brigade_id,
			argMaxIf(assignment_mode,occurred_at,assignment_mode!='') AS assignment_mode
		FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND topic='tickets.events.v1'
			AND ticket_id!='' AND ` + snapshotWhere + ` GROUP BY ticket_id
	), ages AS (
		SELECT toFloat64(dateDiff('second',created_at,as_of)) AS seconds FROM lifecycle
		WHERE current_status='NEW' AND brigade_id='' AND created_at>toDateTime64(0,3) AND ` + dimensionWhere + `
	)
	SELECT count(),ifNotFinite(avg(seconds),0),ifNotFinite(quantileExact(0.5)(seconds),0),
		ifNotFinite(quantileExact(0.9)(seconds),0),ifNotFinite(quantileExact(0.95)(seconds),0),
		ifNotFinite(quantileExact(0.99)(seconds),0),
		countIf(seconds<300),countIf(seconds>=300 AND seconds<900),countIf(seconds>=900 AND seconds<1800),
		countIf(seconds>=1800 AND seconds<3600),countIf(seconds>=3600) FROM ages`
	var result models.QueueAgeSummary
	var buckets [5]uint64
	err := r.db.QueryRow(ctx, query, args...).Scan(
		&result.Age.SampleCount, &result.Age.AverageSeconds, &result.Age.MedianSeconds,
		&result.Age.P90Seconds, &result.Age.P95Seconds, &result.Age.P99Seconds,
		&buckets[0], &buckets[1], &buckets[2], &buckets[3], &buckets[4],
	)
	if err != nil {
		return models.QueueAgeSummary{}, err
	}
	result.ActiveUnassigned = result.Age.SampleCount
	ranges := []string{"0-5", "5-15", "15-30", "30-60", "60+"}
	result.Buckets = make([]models.QueueAgeBucket, 0, len(ranges))
	for index, name := range ranges {
		result.Buckets = append(result.Buckets, models.QueueAgeBucket{Range: name, Count: buckets[index]})
	}
	return result, nil
}

func (r *AnalyticsRepoStruct) routingEfficiency(ctx context.Context, filter models.Filter) (models.RoutingEfficiency, error) {
	timeWhere, args := buildTimeFilter(filter, "route.occurred_at")
	dimensionWhere, dimensionArgs := buildAssignmentDimensions(filter)
	for _, dimension := range []string{"department_id", "category_id", "priority", "brigade_id", "assignment_mode"} {
		dimensionWhere = strings.ReplaceAll(dimensionWhere, dimension, "ticket."+dimension)
	}
	args = append(args, dimensionArgs...)
	query := `WITH tickets AS (
		SELECT ticket_id,argMaxIf(department_id,occurred_at,department_id!='') department_id,
			argMaxIf(category_id,occurred_at,category_id!='') category_id,argMaxIf(priority,occurred_at,priority!='') priority,
			argMaxIf(brigade_id,occurred_at,brigade_id!='') brigade_id,
			argMaxIf(assignment_mode,occurred_at,assignment_mode!='') assignment_mode,argMax(status,occurred_at) ticket_status
		FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND topic='tickets.events.v1' AND ticket_id!='' GROUP BY ticket_id
	), routes AS (
		SELECT route.route_id route_id,max(ifNull(route.route_revision,0)) revision,
			argMax(route.status,route.occurred_at) route_status,argMax(ifNull(route.distance_meters,0),route.occurred_at) distance_meters,
			any(ticket_status) ticket_status
		FROM (SELECT * FROM domain_events_projection_v1 FINAL) AS route LEFT JOIN tickets AS ticket USING(ticket_id)
		WHERE route.projection_eligible AND route.topic='routing.events.v1' AND route.route_id!='' AND ` + timeWhere + ` AND ` + dimensionWhere + `
		GROUP BY route.route_id
	)
	SELECT count(),sum(revision),countIf(route_status='CANCELLED'),ifNotFinite(avgIf(distance_meters/1000,distance_meters>0),0),
		if(countIf(ticket_status='DONE')=0,0,sumIf(distance_meters/1000,ticket_status='DONE')/countIf(ticket_status='DONE')) FROM routes`
	var result models.RoutingEfficiency
	if err := r.db.QueryRow(ctx, query, args...).Scan(&result.Routes, &result.Recalculations, &result.Cancellations, &result.AverageDistanceKM, &result.KilometersPerCompletedTicket); err != nil {
		return models.RoutingEfficiency{}, err
	}
	funnel := models.Filter{From: filter.From, To: filter.To, DepartmentID: filter.DepartmentID, CategoryID: filter.CategoryID, Priority: filter.Priority, BrigadeID: filter.BrigadeID, AssignmentMode: filter.AssignmentMode}
	where, candidateArgs := buildFilter(funnel, "occurred_at")
	var candidates, reachable uint64
	if err := r.db.QueryRow(ctx, `SELECT sum(ifNull(candidate_count,0)),sum(ifNull(reachable_candidate_count,0)) FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND topic='dispatch.events.v1' AND lowerUTF8(event_type)='dispatch.candidates_ranked' AND `+where, candidateArgs...).Scan(&candidates, &reachable); err != nil {
		return models.RoutingEfficiency{}, err
	}
	if candidates > 0 && candidates > reachable {
		result.UnreachableCandidateRate = float64(candidates-reachable) / float64(candidates) * 100
	}
	eta, err := r.etaAccuracy(ctx, filter)
	if err != nil {
		return models.RoutingEfficiency{}, err
	}
	result.ETASampleCount = eta.ETASampleCount
	result.ETAMeanAbsoluteErrorSeconds = eta.ETAMeanAbsoluteErrorSeconds
	result.ETABiasSeconds = eta.ETABiasSeconds
	result.ETAP95AbsoluteErrorSeconds = eta.ETAP95AbsoluteErrorSeconds
	result.ETAWithinFiveMinutesRate = eta.ETAWithinFiveMinutesRate
	return result, nil
}

func (r *AnalyticsRepoStruct) etaAccuracy(ctx context.Context, filter models.Filter) (models.RoutingEfficiency, error) {
	timeWhere, args := buildTimeFilter(filter, "route.occurred_at")
	dimensionWhere, dimensionArgs := buildAssignmentDimensions(filter)
	for _, dimension := range []string{"department_id", "category_id", "priority", "brigade_id", "assignment_mode"} {
		dimensionWhere = strings.ReplaceAll(dimensionWhere, dimension, "ticket."+dimension)
	}
	args = append(args, dimensionArgs...)
	query := `WITH tickets AS (
		SELECT ticket_id,argMaxIf(department_id,occurred_at,department_id!='') department_id,
			argMaxIf(category_id,occurred_at,category_id!='') category_id,argMaxIf(priority,occurred_at,priority!='') priority,
			argMaxIf(brigade_id,occurred_at,brigade_id!='') brigade_id,
			argMaxIf(assignment_mode,occurred_at,assignment_mode!='') assignment_mode
		FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND topic='tickets.events.v1' AND ticket_id!='' GROUP BY ticket_id
	), predictions AS (
		SELECT route.route_id route_id,any(route.brigade_id) brigade_id,
			argMax(route.occurred_at,ifNull(route.route_revision,0)) predicted_at,
			argMax(ifNull(route.duration_seconds,0),ifNull(route.route_revision,0)) duration_seconds,
			argMax(ifNull(route.destination_latitude,0),ifNull(route.route_revision,0)) destination_latitude,
			argMax(ifNull(route.destination_longitude,0),ifNull(route.route_revision,0)) destination_longitude
		FROM (SELECT * FROM domain_events_projection_v1 FINAL) AS route LEFT JOIN tickets AS ticket USING(ticket_id)
		WHERE route.projection_eligible AND route.topic='routing.events.v1'
			AND lowerUTF8(route.event_type) IN ('routing.route.created.v1','routing.route.recalculated.v1')
			AND route.route_id!='' AND route.duration_seconds>0 AND route.destination_latitude IS NOT NULL
			AND route.destination_longitude IS NOT NULL AND ` + timeWhere + ` AND ` + dimensionWhere + `
		GROUP BY route.route_id
	), arrivals AS (
		SELECT prediction.route_id,prediction.predicted_at,prediction.duration_seconds,
			minIf(position.occurred_at,position.occurred_at>prediction.predicted_at
				AND greatCircleDistance(position.longitude,position.latitude,prediction.destination_longitude,prediction.destination_latitude)
				<=greatest(100,ifNull(position.accuracy_meters,100))) actual_at
		FROM predictions prediction LEFT JOIN (
			SELECT * FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND topic='locations.events.v1'
				AND lowerUTF8(event_type)='vehiclepositionupdated' AND latitude IS NOT NULL AND longitude IS NOT NULL
		) position ON position.brigade_id=prediction.brigade_id
		GROUP BY prediction.route_id,prediction.predicted_at,prediction.duration_seconds
	), errors AS (
		SELECT toFloat64(dateDiff('second',addSeconds(predicted_at,toInt64(duration_seconds)),actual_at)) error_seconds
		FROM arrivals WHERE actual_at>toDateTime64(0,3)
	)
	SELECT count(),ifNotFinite(avg(abs(error_seconds)),0),ifNotFinite(avg(error_seconds),0),
		ifNotFinite(quantileExact(0.95)(abs(error_seconds)),0),
		if(count()=0,0,countIf(abs(error_seconds)<=300)/count()*100) FROM errors`
	var result models.RoutingEfficiency
	err := r.db.QueryRow(ctx, query, args...).Scan(
		&result.ETASampleCount, &result.ETAMeanAbsoluteErrorSeconds, &result.ETABiasSeconds,
		&result.ETAP95AbsoluteErrorSeconds, &result.ETAWithinFiveMinutesRate,
	)
	return result, err
}

func (r *AnalyticsRepoStruct) capacityForecast(ctx context.Context, filter models.Filter) (models.CapacityForecast, error) {
	where, args := buildFilter(filter, "occurred_at")
	query := `WITH source AS (
		SELECT occurred_at FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND topic='tickets.events.v1'
			AND lowerUTF8(event_type)='ticket.created' AND ` + where + `
	), daily AS (SELECT toDate(occurred_at) day,count() value FROM source GROUP BY day),
	 hourly AS (SELECT toStartOfHour(occurred_at) hour,count() value FROM source GROUP BY hour)
	SELECT (SELECT count() FROM daily),(SELECT ifNotFinite(avg(value),0) FROM daily),
		(SELECT ifNotFinite(max(value),0) FROM hourly)`
	var result models.CapacityForecast
	var observedDays, peakHourlyIncoming uint64
	if err := r.db.QueryRow(ctx, query, args...).Scan(&observedDays, &result.AverageDailyIncoming, &peakHourlyIncoming); err != nil {
		return models.CapacityForecast{}, err
	}
	result.ObservedDays = uint32(min(observedDays, uint64(^uint32(0))))
	result.PeakHourlyIncoming = float64(peakHourlyIncoming)
	result.ForecastNextDay = result.AverageDailyIncoming
	overview, err := r.Overview(ctx, filter)
	if err != nil {
		return models.CapacityForecast{}, err
	}
	result.RequiredBrigades = uint64(math.Ceil(result.PeakHourlyIncoming * overview.AvgResolutionSeconds / 3600))
	result.Formula = "ceil(peak_hourly_incoming × average_resolution_seconds / 3600)"
	return result, nil
}

func (r *AnalyticsRepoStruct) eligibleBrigadeIDs(ctx context.Context, filter models.Filter) ([]string, error) {
	snapshotWhere := "1=1"
	args := make([]any, 0, 3)
	if filter.To != nil {
		snapshotWhere += " AND occurred_at<=?"
		args = append(args, *filter.To)
	}
	dimensionWhere := "department_id!=''"
	if filter.DepartmentID != nil {
		dimensionWhere += " AND department_id=?"
		args = append(args, *filter.DepartmentID)
	}
	if filter.BrigadeID != nil {
		dimensionWhere += " AND brigade_id=?"
		args = append(args, *filter.BrigadeID)
	}
	query := `WITH lifecycle AS (
		SELECT entity_id AS brigade_id,
			argMaxIf(department_id,occurred_at,department_id!='') AS department_id,
			argMaxIf(status,occurred_at,status!='') AS current_status
		FROM domain_events_projection_v1 FINAL
		WHERE projection_eligible AND topic='brigades.events.v1' AND entity_id!='' AND ` + snapshotWhere + `
		GROUP BY entity_id
	)
	SELECT brigade_id FROM lifecycle
	WHERE current_status IN ('ACTIVE','AVAILABLE','BUSY','ON_ROUTE','ON_SITE') AND ` + dimensionWhere + `
	ORDER BY brigade_id`
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func mergeEligibleBrigades(items []models.BrigadeWorkloadItem, eligible []string) []models.BrigadeWorkloadItem {
	byID := make(map[string]models.BrigadeWorkloadItem, len(items)+len(eligible))
	for _, item := range items {
		byID[item.BrigadeID] = item
	}
	for _, id := range eligible {
		if _, exists := byID[id]; !exists {
			byID[id] = models.BrigadeWorkloadItem{BrigadeID: id}
		}
	}
	result := make([]models.BrigadeWorkloadItem, 0, len(byID))
	for _, item := range byID {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].BrigadeID < result[j].BrigadeID })
	return result
}

func applyWorkloadBalance(result *models.BrigadeWorkload) {
	result.BrigadeCount = uint64(len(result.Brigades))
	if len(result.Brigades) == 0 {
		return
	}
	active := make([]uint64, len(result.Brigades))
	var sum uint64
	for index, item := range result.Brigades {
		active[index] = item.Active
		sum += item.Active
		if item.Active > result.MaxActive {
			result.MaxActive = item.Active
		}
	}
	result.AverageActive = float64(sum) / float64(len(active))
	for _, value := range active {
		delta := float64(value) - result.AverageActive
		result.StandardDeviation += delta * delta
	}
	result.StandardDeviation = math.Sqrt(result.StandardDeviation / float64(len(active)))
	if result.AverageActive > 0 {
		result.CoefficientOfVariation = result.StandardDeviation / result.AverageActive
	}
	if sum == 0 {
		return
	}
	sort.Slice(active, func(i, j int) bool { return active[i] < active[j] })
	var weightedSum float64
	for index, value := range active {
		weightedSum += float64(index+1) * float64(value)
	}
	n := float64(len(active))
	result.Gini = 2*weightedSum/(n*float64(sum)) - (n+1)/n
}

func (r *AnalyticsRepoStruct) ActiveWorkers(ctx context.Context, filter models.Filter) (models.ActiveWorkers, error) {
	total, err := r.activeWorkerGroups(ctx, filter, "TOTAL", "'TOTAL'")
	if err != nil {
		return models.ActiveWorkers{}, err
	}
	byDepartment, err := r.activeWorkerGroups(ctx, filter, "DEPARTMENT", "department_id")
	if err != nil {
		return models.ActiveWorkers{}, err
	}
	byBrigade, err := r.activeWorkerGroups(ctx, filter, "BRIGADE", "brigade_id")
	if err != nil {
		return models.ActiveWorkers{}, err
	}
	result := models.ActiveWorkers{ByDepartment: byDepartment, ByBrigade: byBrigade}
	if len(total) == 1 {
		result.ActiveMembers = total[0].ActiveMembers
		result.Available = total[0].Available
		result.OnShift = total[0].OnShift
	}
	return result, nil
}

func (r *AnalyticsRepoStruct) AssignmentFunnel(ctx context.Context, filter models.Filter) (models.AssignmentFunnel, error) {
	cte, args := assignmentFunnelLifecycle(filter)
	query := cte + ` SELECT
		count(),
		countIf(candidates_at>toDateTime64(0,3)),
		countIf(reserved_at>toDateTime64(0,3)),
		countIf(route_built_at>toDateTime64(0,3)),
		countIf(assigned_at>toDateTime64(0,3))
	FROM filtered`
	counts := make([]uint64, 5)
	if err := r.db.QueryRow(ctx, query, args...).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4]); err != nil {
		return models.AssignmentFunnel{}, err
	}
	names := []string{"REQUESTED", "CANDIDATES_FOUND", "RESERVED", "ROUTE_BUILT", "ASSIGNED"}
	columns := [][2]string{{"", "requested_at"}, {"requested_at", "candidates_at"}, {"candidates_at", "reserved_at"}, {"reserved_at", "route_built_at"}, {"route_built_at", "assigned_at"}}
	stages := make([]models.AssignmentFunnelStage, 0, len(names))
	for index, name := range names {
		stage := models.AssignmentFunnelStage{Stage: name, Count: counts[index]}
		if index == 0 {
			stage.ConversionFromPrevious = 100
		} else if counts[index-1] > 0 {
			stage.ConversionFromPrevious = float64(counts[index]) / float64(counts[index-1]) * 100
		}
		if columns[index][0] != "" {
			var err error
			stage.TransitionTime, err = r.assignmentFunnelTransition(ctx, filter, columns[index][0], columns[index][1])
			if err != nil {
				return models.AssignmentFunnel{}, err
			}
		}
		stages = append(stages, stage)
	}
	return models.AssignmentFunnel{Stages: stages}, nil
}

func (r *AnalyticsRepoStruct) assignmentFunnelTransition(ctx context.Context, filter models.Filter, fromColumn, toColumn string) (models.LatencyDistribution, error) {
	allowed := map[string]bool{"requested_at": true, "candidates_at": true, "reserved_at": true, "route_built_at": true, "assigned_at": true}
	if !allowed[fromColumn] || !allowed[toColumn] {
		return models.LatencyDistribution{}, fmt.Errorf("invalid funnel transition %s -> %s", fromColumn, toColumn)
	}
	cte, args := assignmentFunnelLifecycle(filter)
	query := cte + `, durations AS (
		SELECT dateDiff('millisecond',` + fromColumn + `,` + toColumn + `)/1000.0 AS seconds
		FROM filtered WHERE ` + toColumn + `>` + fromColumn + ` AND ` + fromColumn + `>toDateTime64(0,3)
	) SELECT count(),ifNotFinite(avg(seconds),0),ifNotFinite(quantileExact(0.5)(seconds),0),ifNotFinite(quantileExact(0.9)(seconds),0),ifNotFinite(quantileExact(0.95)(seconds),0),ifNotFinite(quantileExact(0.99)(seconds),0) FROM durations`
	return scanLatency(r.db.QueryRow(ctx, query, args...))
}

func assignmentFunnelLifecycle(filter models.Filter) (string, []any) {
	timeWhere, args := buildTimeFilter(filter, "occurred_at")
	dimensionWhere, dimensionArgs := buildAssignmentDimensions(filter)
	args = append(args, dimensionArgs...)
	return `WITH events AS (
		SELECT * FROM domain_events_projection_v1 FINAL
		WHERE projection_eligible AND topic='dispatch.events.v1' AND ` + timeWhere + `
	), lifecycle AS (
		SELECT entity_id AS operation_id,
			minIf(occurred_at,lowerUTF8(event_type)='dispatch.requested') AS requested_at,
			minIf(occurred_at,lowerUTF8(event_type)='dispatch.candidates_ranked' AND ifNull(candidate_count,0)>0) AS candidates_at,
			minIf(occurred_at,lowerUTF8(event_type)='dispatch.reserved') AS reserved_at,
			minIf(occurred_at,lowerUTF8(event_type)='dispatch.route_built') AS route_built_at,
			minIf(occurred_at,lowerUTF8(event_type)='dispatch.assigned') AS assigned_at,
			argMaxIf(department_id,occurred_at,department_id!='') AS department_id,
			argMaxIf(category_id,occurred_at,category_id!='') AS category_id,
			argMaxIf(priority,occurred_at,priority!='') AS priority,
			argMaxIf(brigade_id,occurred_at,brigade_id!='') AS brigade_id,
			argMaxIf(assignment_mode,occurred_at,assignment_mode!='') AS assignment_mode
		FROM events WHERE entity_id!='' GROUP BY entity_id
	), filtered AS (
		SELECT * FROM lifecycle WHERE requested_at>toDateTime64(0,3) AND ` + dimensionWhere + `
	)`, args
}

func (r *AnalyticsRepoStruct) activeWorkerGroups(ctx context.Context, filter models.Filter, dimension, expression string) ([]models.ActiveWorkerGroup, error) {
	if expression != "'TOTAL'" && expression != "department_id" && expression != "brigade_id" {
		return nil, fmt.Errorf("invalid active worker dimension %q", dimension)
	}
	snapshotWhere := "1=1"
	args := make([]any, 0, 3)
	if filter.To != nil {
		snapshotWhere += " AND occurred_at<=?"
		args = append(args, *filter.To)
	}
	dimensionWhere := "1=1"
	if filter.DepartmentID != nil {
		dimensionWhere += " AND department_id=?"
		args = append(args, *filter.DepartmentID)
	}
	if filter.BrigadeID != nil {
		dimensionWhere += " AND brigade_id=?"
		args = append(args, *filter.BrigadeID)
	}
	snapshotAt := time.Now().UTC()
	if filter.To != nil && filter.To.Before(snapshotAt) {
		snapshotAt = *filter.To
	}
	query := `WITH shift_lifecycle AS (
		SELECT shift_id,
			argMaxIf(brigade_id,occurred_at,brigade_id!='') AS brigade_id,
			minIf(occurred_at,lowerUTF8(event_type)='brigadeshiftstarted') AS started_at,
			maxIf(occurred_at,lowerUTF8(event_type)='brigadeshiftended') AS ended_at
		FROM domain_events_projection_v1 FINAL
		WHERE projection_eligible AND shift_id!='' AND occurred_at<=? GROUP BY shift_id
	), active_shift_brigades AS (
		SELECT DISTINCT brigade_id FROM shift_lifecycle
		WHERE brigade_id!='' AND started_at>toDateTime64(0,3) AND ended_at=toDateTime64(0,3)
	), lifecycle AS (
		SELECT member_id,
			argMaxIf(department_id,occurred_at,department_id!='') AS department_id,
			argMaxIf(brigade_id,occurred_at,brigade_id!='') AS brigade_id,
			argMax(member_status,occurred_at) AS member_status,
			argMax(availability_status,occurred_at) AS availability_status,
			argMax(member_active,occurred_at) AS member_active
		FROM domain_events_projection_v1 FINAL
		WHERE projection_eligible AND topic='brigades.events.v1' AND member_id!='' AND ` + snapshotWhere + `
		GROUP BY member_id
	), filtered AS (
		SELECT * FROM lifecycle WHERE ` + dimensionWhere + `
	)
	SELECT toString(` + expression + `),
		countIf(ifNull(member_active,false) AND member_status!='REMOVED'),
		countIf(ifNull(member_active,false) AND member_status!='REMOVED' AND availability_status='AVAILABLE'),
		countIf(ifNull(member_active,false) AND member_status!='REMOVED' AND brigade_id IN (SELECT brigade_id FROM active_shift_brigades))
	FROM filtered GROUP BY ` + expression + ` HAVING toString(` + expression + `)!='' ORDER BY toString(` + expression + `)`
	queryArgs := append([]any{snapshotAt}, args...)
	rows, err := r.db.Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]models.ActiveWorkerGroup, 0)
	for rows.Next() {
		item := models.ActiveWorkerGroup{Dimension: dimension}
		if err = rows.Scan(&item.Key, &item.ActiveMembers, &item.Available, &item.OnShift); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *AnalyticsRepoStruct) dispatchFailureBreakdown(ctx context.Context, filter models.Filter, column string, total uint64) ([]models.DispatchFailureBreakdown, error) {
	if column != "failure_stage" && column != "failure_code" {
		return nil, fmt.Errorf("invalid dispatch failure breakdown %q", column)
	}
	cte, args := dispatchFailureLifecycle(filter)
	rows, err := r.db.Query(ctx, cte+` SELECT `+column+` AS key,count() AS count
		FROM filtered
		WHERE terminal_status IN ('FAILED','EXPIRED','CANCELED','CANCELLED') AND key!=''
		GROUP BY key ORDER BY count DESC,key`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]models.DispatchFailureBreakdown, 0)
	for rows.Next() {
		var item models.DispatchFailureBreakdown
		if err = rows.Scan(&item.Key, &item.Count); err != nil {
			return nil, err
		}
		if total > 0 {
			item.Percent = float64(item.Count) / float64(total) * 100
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *AnalyticsRepoStruct) dispatchBusinessReasons(ctx context.Context, filter models.Filter, requested uint64) ([]models.DispatchFailureReasonSummary, error) {
	cte, args := dispatchFailureLifecycle(filter)
	rows, err := r.db.Query(ctx, cte+dispatchFailureClassification+` SELECT business_reason,count() AS count
		FROM classified WHERE business_reason!=''
		GROUP BY business_reason ORDER BY count DESC,business_reason`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]models.DispatchFailureReasonSummary, 0, 3)
	for rows.Next() {
		var item models.DispatchFailureReasonSummary
		if err = rows.Scan(&item.Reason, &item.Count); err != nil {
			return nil, err
		}
		if requested > 0 {
			item.RequestRate = float64(item.Count) / float64(requested) * 100
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *AnalyticsRepoStruct) dispatchReasonDimensions(ctx context.Context, filter models.Filter, column string) ([]models.DispatchFailureReasonDimension, error) {
	if column != "department_id" && column != "category_id" {
		return nil, fmt.Errorf("invalid dispatch reason dimension %q", column)
	}
	cte, args := dispatchFailureLifecycle(filter)
	rows, err := r.db.Query(ctx, cte+dispatchFailureClassification+`, grouped AS (
		SELECT business_reason,`+column+` AS key,count() AS count
		FROM classified WHERE business_reason!='' AND key!=''
		GROUP BY business_reason,key
	), ranked AS (
		SELECT business_reason,key,count,
			row_number() OVER (PARTITION BY business_reason ORDER BY count DESC,key) AS position,
			sum(count) OVER (PARTITION BY business_reason) AS reason_total
		FROM grouped
	) SELECT business_reason,key,count,reason_total
		FROM ranked WHERE position<=10 ORDER BY business_reason,count DESC,key`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]models.DispatchFailureReasonDimension, 0)
	for rows.Next() {
		var item models.DispatchFailureReasonDimension
		var reasonTotal uint64
		if err = rows.Scan(&item.Reason, &item.Key, &item.Count, &reasonTotal); err != nil {
			return nil, err
		}
		if reasonTotal > 0 {
			item.ReasonPercent = float64(item.Count) / float64(reasonTotal) * 100
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

const dispatchFailureClassification = `, classified AS (
	SELECT *,multiIf(
		terminal_status='EXPIRED' OR failure_code='RESERVATION_EXPIRED','RESERVATION_EXPIRED',
		failure_code IN ('NO_REACHABLE_BRIGADE','NO_CANDIDATES'),'NO_SUITABLE_BRIGADE',
		terminal_status='FAILED' AND failure_stage='ROUTING','NO_ROUTE',
		''
	) AS business_reason FROM filtered
)`

func dispatchFailureLifecycle(filter models.Filter) (string, []any) {
	timeWhere, args := buildTimeFilter(filter, "occurred_at")
	dimensionWhere, dimensionArgs := buildDispatchFailureDimensions(filter)
	args = append(args, dimensionArgs...)
	return `WITH events AS (
		SELECT * FROM domain_events_projection_v1 FINAL
		WHERE projection_eligible AND topic='dispatch.events.v1' AND ` + timeWhere + `
	), lifecycle AS (
		SELECT entity_id AS operation_id,
			argMaxIf(ticket_id,occurred_at,ticket_id!='') AS ticket_id,
			countIf(lowerUTF8(event_type)='dispatch.requested')>0 AS requested,
			minIf(occurred_at,lowerUTF8(event_type)='dispatch.requested') AS requested_at,
			max(occurred_at) AS updated_at,
			argMax(status,occurred_at) AS terminal_status,
			argMaxIf(trace_id,occurred_at,trace_id!='') AS trace_id,
			argMaxIf(department_id,occurred_at,department_id!='') AS department_id,
			argMaxIf(category_id,occurred_at,category_id!='') AS category_id,
			argMaxIf(priority,occurred_at,priority!='') AS priority,
			argMaxIf(brigade_id,occurred_at,brigade_id!='') AS brigade_id,
			argMaxIf(assignment_mode,occurred_at,assignment_mode!='') AS assignment_mode,
			argMaxIf(failure_stage,occurred_at,failure_stage!='') AS failure_stage,
			argMaxIf(failure_code,occurred_at,failure_code!='') AS failure_code
		FROM events WHERE entity_id!='' GROUP BY entity_id
	), filtered AS (
		SELECT * FROM lifecycle WHERE ` + dimensionWhere + `
	)`, args
}

func (r *AnalyticsRepoStruct) OperationalLatency(ctx context.Context, filter models.Filter, groupBy string) (models.OperationalLatency, error) {
	assignment, err := r.assignmentLatency(ctx, filter)
	if err != nil {
		return models.OperationalLatency{}, err
	}
	routing, err := r.routingLatency(ctx, filter)
	if err != nil {
		return models.OperationalLatency{}, err
	}
	result := models.OperationalLatency{
		AssignmentTime:         assignment,
		RoutingCalculationTime: routing,
	}
	if groupBy == "" || groupBy == "UNSPECIFIED" {
		return result, nil
	}
	groups, err := r.groupedLatency(ctx, filter, groupBy)
	if err != nil {
		return models.OperationalLatency{}, err
	}
	result.Groups = groups
	return result, nil
}

func (r *AnalyticsRepoStruct) assignmentLatency(ctx context.Context, filter models.Filter) (models.LatencyDistribution, error) {
	timeWhere, args := buildTimeFilter(filter, "occurred_at")
	dimensionWhere, dimensionArgs := buildAssignmentDimensions(filter)
	args = append(args, dimensionArgs...)
	query := `WITH events AS (
		SELECT * FROM domain_events_projection_v1 FINAL
		WHERE projection_eligible AND topic IN ('tickets.events.v1','dispatch.events.v1') AND ` + timeWhere + `
	), lifecycle AS (
		SELECT ticket_id,
			minIf(occurred_at, lowerUTF8(event_type)='ticket.created') AS created_at,
			minIf(occurred_at, lowerUTF8(event_type)='dispatch.requested') AS requested_at,
			minIf(occurred_at, lowerUTF8(event_type) IN ('dispatch.assigned','ticket.assigned') OR (lowerUTF8(event_type)='ticket.status_changed' AND status IN ('ASSIGNED','IN_PROGRESS'))) AS assigned_at,
			argMaxIf(department_id,occurred_at,department_id!='') AS department_id,
			argMaxIf(category_id,occurred_at,category_id!='') AS category_id,
			argMaxIf(priority,occurred_at,priority!='') AS priority,
			argMaxIf(brigade_id,occurred_at,brigade_id!='') AS brigade_id,
			argMaxIf(assignment_mode,occurred_at,assignment_mode!='') AS assignment_mode
		FROM events WHERE ticket_id!='' GROUP BY ticket_id
	), durations AS (
		SELECT dateDiff('millisecond', if(requested_at>toDateTime64(0,3),requested_at,created_at), assigned_at)/1000.0 AS seconds
		FROM lifecycle
		WHERE assigned_at>if(requested_at>toDateTime64(0,3),requested_at,created_at) AND ` + dimensionWhere + `
	)
	SELECT count(),ifNotFinite(avg(seconds),0),ifNotFinite(quantileExact(0.5)(seconds),0),ifNotFinite(quantileExact(0.9)(seconds),0),ifNotFinite(quantileExact(0.95)(seconds),0),ifNotFinite(quantileExact(0.99)(seconds),0) FROM durations`
	return scanLatency(r.db.QueryRow(ctx, query, args...))
}

func (r *AnalyticsRepoStruct) routingLatency(ctx context.Context, filter models.Filter) (models.LatencyDistribution, error) {
	timeWhere, args := buildTimeFilter(filter, "route.occurred_at")
	dimensionWhere, dimensionArgs := buildRoutingDimensions(filter)
	args = append(args, dimensionArgs...)
	query := `WITH operation_dimensions AS (
		SELECT ticket_id,
			argMaxIf(department_id,occurred_at,department_id!='') AS department_id,
			argMaxIf(category_id,occurred_at,category_id!='') AS category_id,
			argMaxIf(priority,occurred_at,priority!='') AS priority,
			argMaxIf(assignment_mode,occurred_at,assignment_mode!='') AS assignment_mode
		FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND topic IN ('tickets.events.v1','dispatch.events.v1') AND ticket_id!='' GROUP BY ticket_id
	), routing_events AS (
		SELECT route.ticket_id AS ticket_id,
			if(route.department_id!='',route.department_id,ticket.department_id) AS department_id,
			if(route.category_id!='',route.category_id,ticket.category_id) AS category_id,
			if(route.priority!='',route.priority,ticket.priority) AS priority,
			route.brigade_id AS brigade_id,
			if(route.assignment_mode!='',route.assignment_mode,ticket.assignment_mode) AS assignment_mode,
			route.failure_code AS failure_code,
			route.success AS success,
			route.engine AS engine,
			route.travel_mode AS travel_mode,
			route.calculation_duration_ms AS calculation_duration_ms
		FROM domain_events AS route FINAL
		LEFT JOIN operation_dimensions AS ticket ON route.ticket_id=ticket.ticket_id
		WHERE route.projection_eligible AND route.topic='routing.events.v1' AND route.calculation_duration_ms IS NOT NULL AND route.calculation_duration_ms>=0 AND ` + timeWhere + `
	), durations AS (
		SELECT calculation_duration_ms/1000.0 AS seconds FROM routing_events WHERE ` + dimensionWhere + `
	)
	SELECT count(),ifNotFinite(avg(seconds),0),ifNotFinite(quantileExact(0.5)(seconds),0),ifNotFinite(quantileExact(0.9)(seconds),0),ifNotFinite(quantileExact(0.95)(seconds),0),ifNotFinite(quantileExact(0.99)(seconds),0) FROM durations`
	return scanLatency(r.db.QueryRow(ctx, query, args...))
}

func (r *AnalyticsRepoStruct) groupedLatency(ctx context.Context, filter models.Filter, dimension string) ([]models.OperationalLatencyGroup, error) {
	dimension = strings.ToUpper(strings.TrimSpace(dimension))
	groups := make(map[string]*models.OperationalLatencyGroup)
	if column, ok := assignmentGroupColumn(dimension); ok {
		values, err := r.groupedAssignmentLatency(ctx, filter, column)
		if err != nil {
			return nil, err
		}
		for key, distribution := range values {
			groups[key] = &models.OperationalLatencyGroup{Dimension: dimension, Key: key, AssignmentTime: distribution}
		}
	}
	if expression, ok := routingGroupExpression(dimension); ok {
		values, err := r.groupedRoutingLatency(ctx, filter, expression)
		if err != nil {
			return nil, err
		}
		for key, distribution := range values {
			group := groups[key]
			if group == nil {
				group = &models.OperationalLatencyGroup{Dimension: dimension, Key: key}
				groups[key] = group
			}
			group.RoutingCalculationTime = distribution
		}
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("invalid operational latency dimension %q", dimension)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]models.OperationalLatencyGroup, 0, len(keys))
	for _, key := range keys {
		result = append(result, *groups[key])
	}
	return result, nil
}

func assignmentGroupColumn(dimension string) (string, bool) {
	column, ok := map[string]string{
		"DEPARTMENT":      "department_id",
		"CATEGORY":        "category_id",
		"PRIORITY":        "priority",
		"ASSIGNMENT_MODE": "assignment_mode",
		"BRIGADE":         "brigade_id",
	}[dimension]
	return column, ok
}

func routingGroupExpression(dimension string) (string, bool) {
	expression, ok := map[string]string{
		"DEPARTMENT":      "department_id",
		"CATEGORY":        "category_id",
		"PRIORITY":        "priority",
		"ASSIGNMENT_MODE": "assignment_mode",
		"BRIGADE":         "brigade_id",
		"ENGINE":          "engine",
		"TRAVEL_MODE":     "travel_mode",
		"SUCCESS":         "ifNull(toString(success),'unknown')",
		"FAILURE_CODE":    "failure_code",
	}[dimension]
	return expression, ok
}

func (r *AnalyticsRepoStruct) groupedAssignmentLatency(ctx context.Context, filter models.Filter, column string) (map[string]models.LatencyDistribution, error) {
	timeWhere, args := buildTimeFilter(filter, "occurred_at")
	dimensionWhere, dimensionArgs := buildAssignmentDimensions(filter)
	args = append(args, dimensionArgs...)
	query := `WITH events AS (
		SELECT * FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND topic IN ('tickets.events.v1','dispatch.events.v1') AND ` + timeWhere + `
	), lifecycle AS (
		SELECT ticket_id,minIf(occurred_at,lowerUTF8(event_type)='ticket.created') created_at,
			minIf(occurred_at,lowerUTF8(event_type)='dispatch.requested') requested_at,
			minIf(occurred_at,lowerUTF8(event_type) IN ('dispatch.assigned','ticket.assigned') OR (lowerUTF8(event_type)='ticket.status_changed' AND status IN ('ASSIGNED','IN_PROGRESS'))) assigned_at,
			argMaxIf(department_id,occurred_at,department_id!='') department_id,argMaxIf(category_id,occurred_at,category_id!='') category_id,
			argMaxIf(priority,occurred_at,priority!='') priority,argMaxIf(brigade_id,occurred_at,brigade_id!='') brigade_id,
			argMaxIf(assignment_mode,occurred_at,assignment_mode!='') assignment_mode
		FROM events WHERE ticket_id!='' GROUP BY ticket_id
	), durations AS (
		SELECT toString(` + column + `) key,dateDiff('millisecond',if(requested_at>toDateTime64(0,3),requested_at,created_at),assigned_at)/1000.0 seconds
		FROM lifecycle WHERE assigned_at>if(requested_at>toDateTime64(0,3),requested_at,created_at) AND ` + dimensionWhere + `
	) SELECT key,count(),ifNotFinite(avg(seconds),0),ifNotFinite(quantileExact(0.5)(seconds),0),ifNotFinite(quantileExact(0.9)(seconds),0),ifNotFinite(quantileExact(0.95)(seconds),0),ifNotFinite(quantileExact(0.99)(seconds),0)
	FROM durations WHERE key!='' GROUP BY key ORDER BY key`
	return scanLatencyGroups(r.db.Query(ctx, query, args...))
}

func (r *AnalyticsRepoStruct) groupedRoutingLatency(ctx context.Context, filter models.Filter, expression string) (map[string]models.LatencyDistribution, error) {
	timeWhere, args := buildTimeFilter(filter, "route.occurred_at")
	dimensionWhere, dimensionArgs := buildRoutingDimensions(filter)
	args = append(args, dimensionArgs...)
	query := `WITH operation_dimensions AS (
		SELECT ticket_id,argMaxIf(department_id,occurred_at,department_id!='') department_id,argMaxIf(category_id,occurred_at,category_id!='') category_id,
			argMaxIf(priority,occurred_at,priority!='') priority,argMaxIf(assignment_mode,occurred_at,assignment_mode!='') assignment_mode
		FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND topic IN ('tickets.events.v1','dispatch.events.v1') AND ticket_id!='' GROUP BY ticket_id
	), routing_events AS (
		SELECT if(route.department_id!='',route.department_id,ticket.department_id) department_id,
			if(route.category_id!='',route.category_id,ticket.category_id) category_id,if(route.priority!='',route.priority,ticket.priority) priority,
			route.brigade_id brigade_id,if(route.assignment_mode!='',route.assignment_mode,ticket.assignment_mode) assignment_mode,
			route.failure_code failure_code,route.success success,route.engine engine,route.travel_mode travel_mode,route.calculation_duration_ms calculation_duration_ms
		FROM domain_events AS route FINAL LEFT JOIN operation_dimensions ticket ON route.ticket_id=ticket.ticket_id
		WHERE route.projection_eligible AND route.topic='routing.events.v1' AND route.calculation_duration_ms IS NOT NULL AND route.calculation_duration_ms>=0 AND ` + timeWhere + `
	), durations AS (SELECT toString(` + expression + `) key,calculation_duration_ms/1000.0 seconds FROM routing_events WHERE ` + dimensionWhere + `)
	SELECT key,count(),ifNotFinite(avg(seconds),0),ifNotFinite(quantileExact(0.5)(seconds),0),ifNotFinite(quantileExact(0.9)(seconds),0),ifNotFinite(quantileExact(0.95)(seconds),0),ifNotFinite(quantileExact(0.99)(seconds),0)
	FROM durations WHERE key!='' GROUP BY key ORDER BY key`
	return scanLatencyGroups(r.db.Query(ctx, query, args...))
}

func scanLatencyGroups(rows driver.Rows, err error) (map[string]models.LatencyDistribution, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]models.LatencyDistribution)
	for rows.Next() {
		var key string
		var distribution models.LatencyDistribution
		if err = rows.Scan(&key, &distribution.SampleCount, &distribution.AverageSeconds, &distribution.MedianSeconds, &distribution.P90Seconds, &distribution.P95Seconds, &distribution.P99Seconds); err != nil {
			return nil, err
		}
		result[key] = distribution
	}
	return result, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanLatency(row rowScanner) (models.LatencyDistribution, error) {
	var latency models.LatencyDistribution
	err := row.Scan(
		&latency.SampleCount,
		&latency.AverageSeconds,
		&latency.MedianSeconds,
		&latency.P90Seconds,
		&latency.P95Seconds,
		&latency.P99Seconds,
	)
	return latency, err
}

func (r *AnalyticsRepoStruct) Overview(ctx context.Context, f models.Filter) (models.Overview, error) {
	where, args := buildFilter(f, "occurred_at")
	query := `WITH events AS (SELECT * FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND topic='tickets.events.v1' AND ` + where + `), tickets AS (SELECT ticket_id,minIf(occurred_at,event_type='ticket.created') created_at,minIf(occurred_at,event_type IN ('ticket.assigned','ticket.status_changed') AND status IN ('ASSIGNED','IN_PROGRESS')) response_at,minIf(occurred_at,event_type='ticket.completed') completed_at,argMax(status,occurred_at) current_status FROM events WHERE ticket_id!='' GROUP BY ticket_id) SELECT countIf(created_at>toDateTime64(0,3)),countIf(completed_at>toDateTime64(0,3)),countIf(current_status='CANCELED'),countIf(current_status NOT IN ('DONE','CANCELED')),if(count()=0,0,countIf(completed_at>toDateTime64(0,3))/count()*100),ifNotFinite(avgIf(dateDiff('second',created_at,response_at),response_at>created_at),0),ifNotFinite(avgIf(dateDiff('second',created_at,completed_at),completed_at>created_at),0) FROM tickets`
	var v models.Overview
	err := r.db.QueryRow(ctx, query, args...).Scan(&v.Created, &v.Completed, &v.Canceled, &v.Active, &v.CompletionRate, &v.AvgResponseSeconds, &v.AvgResolutionSeconds)
	return v, err
}

func (r *AnalyticsRepoStruct) SLA(ctx context.Context, f models.Filter) (models.SLA, error) {
	where, args := buildFilter(f, "occurred_at")
	query := `SELECT countIf(event_type LIKE '%RESPONSE_WARNING%'),countIf(event_type LIKE '%RESPONSE_BREACHED%'),countIf(event_type LIKE '%RESOLUTION_WARNING%'),countIf(event_type LIKE '%RESOLUTION_BREACHED%'),countIf(event_type LIKE '%COMPLETED%'),if(count()=0,0,(countIf(event_type LIKE '%RESPONSE_BREACHED%')+countIf(event_type LIKE '%RESOLUTION_BREACHED%'))/count()*100) FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND topic='sla.events.v1' AND ` + where
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
	query := `WITH source AS (SELECT ` + column + ` key FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND topic='tickets.events.v1' AND event_type='ticket.created' AND ` + where + `), totals AS (SELECT count() total FROM source) SELECT key,count() count,if(total=0,0,count/total*100),total FROM source CROSS JOIN totals WHERE key!='' GROUP BY key,total ORDER BY count DESC LIMIT ?`
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
	query := `SELECT toStartOfDay(occurred_at) day,countIf(topic='tickets.events.v1' AND event_type='ticket.created'),countIf(topic='tickets.events.v1' AND event_type='ticket.completed'),countIf(topic='tickets.events.v1' AND event_type='ticket.canceled'),countIf(topic='sla.events.v1' AND event_type LIKE '%BREACHED%') FROM domain_events_projection_v1 FINAL WHERE projection_eligible AND ` + where + ` GROUP BY day ORDER BY day`
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
	where += " AND projection_eligible AND topic='assets.events.v1'"
	var v models.AssetSummary
	e := r.db.QueryRow(ctx, `SELECT countIf(event_type='asset.CREATED'),countIf(event_type='asset.INCIDENT_RECORDED'),countIf(event_type='asset.INCIDENT_RECORDED' AND JSONExtractBool(payload,'data','Repeated')),countIf(event_type='asset.REPAIR_COMPLETED'),countIf(event_type='asset.INSPECTION_RECORDED'),countIf(event_type='asset.RISK_UPDATED' AND JSONExtractString(payload,'data','Level')='CRITICAL') FROM domain_events_projection_v1 FINAL WHERE `+where, args...).Scan(&v.Created, &v.Incidents, &v.Repeated, &v.Repairs, &v.Inspections, &v.Critical)
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
	rows, e := r.db.Query(ctx, `SELECT `+column+` key,countIf(event_type='asset.INCIDENT_RECORDED') incidents,countIf(event_type='asset.INCIDENT_RECORDED' AND JSONExtractBool(payload,'data','Repeated')),countIf(event_type='asset.REPAIR_COMPLETED'),countIf(event_type='asset.RISK_UPDATED' AND JSONExtractString(payload,'data','Level')='CRITICAL') FROM domain_events_projection_v1 FINAL WHERE `+where+` GROUP BY key HAVING key!='' ORDER BY incidents DESC LIMIT 50`, args...)
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
