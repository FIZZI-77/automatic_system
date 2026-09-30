package repository

import (
	"context"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"analytics/models"
)

type departmentStats struct {
	models.DepartmentPerformance
	responseCount       uint64
	responseSeconds     float64
	resolutionCount     uint64
	resolutionSeconds   float64
	responseDeviation   float64
	resolutionDeviation float64
	ratingSum           uint64
	positiveRatings     uint64
	resolvedRatings     uint64
}

const departmentPerformanceQuery = `WITH tickets AS (
    SELECT ticket_id,
        argMaxIf(department_id,occurred_at,department_id!='') department_id,
        minIf(occurred_at,event_type='ticket.created') created_at,
        minIf(occurred_at,event_type IN ('ticket.assigned','ticket.status_changed') AND status IN ('ASSIGNED','IN_PROGRESS')) response_at,
        minIf(occurred_at,event_type='ticket.completed') completed_at,
        argMaxIf(status,occurred_at,status!='') current_status,
        argMaxIf(JSONExtractUInt(payload,'rating'),occurred_at,event_type='ticket.feedback_submitted') rating,
        argMaxIf(JSONExtractBool(payload,'problem_resolved'),occurred_at,event_type='ticket.feedback_submitted') resolved
    FROM domain_events_projection_v1 FINAL
    WHERE projection_eligible AND topic='tickets.events.v1' AND ticket_id!=''
    GROUP BY ticket_id
), sla AS (
    SELECT ticket_id,
        countIf(event_type='sla.RESPONSE_RECORDED' AND JSONExtractString(payload,'response_deadline')!='' AND JSONExtractString(payload,'responded_at')!='') response_samples,
        maxIf(toUInt8(JSONExtractBool(payload,'response_breached')),event_type='sla.RESPONSE_RECORDED') response_breaches,
        maxIf(ifNull(dateDiff('second',parseDateTime64BestEffortOrNull(JSONExtractString(payload,'response_deadline')),parseDateTime64BestEffortOrNull(JSONExtractString(payload,'responded_at'))),0),event_type='sla.RESPONSE_RECORDED') response_deviation,
        countIf(event_type='sla.COMPLETED' AND JSONExtractString(payload,'resolution_deadline')!='' AND JSONExtractString(payload,'completed_at')!='') resolution_samples,
        maxIf(toUInt8(JSONExtractBool(payload,'resolution_breached')),event_type='sla.COMPLETED') resolution_breaches,
        maxIf(ifNull(dateDiff('second',parseDateTime64BestEffortOrNull(JSONExtractString(payload,'resolution_deadline')),parseDateTime64BestEffortOrNull(JSONExtractString(payload,'completed_at'))),0),event_type='sla.COMPLETED') resolution_deviation
    FROM domain_events_projection_v1 FINAL
    WHERE projection_eligible AND topic='sla.events.v1' AND ticket_id!=''
    GROUP BY ticket_id
)
SELECT department_id,
    count() created,
    countIf(completed_at>toDateTime64(0,3)) completed,
    countIf(current_status IN ('CANCELED','CANCELLED')) canceled,
    countIf(completed_at=toDateTime64(0,3) AND current_status NOT IN ('CANCELED','CANCELLED')) active,
    countIf(response_at>created_at) response_count,
    toFloat64(sumIf(dateDiff('second',created_at,response_at),response_at>created_at)) response_seconds,
    countIf(completed_at>created_at) resolution_count,
    toFloat64(sumIf(dateDiff('second',created_at,completed_at),completed_at>created_at)) resolution_seconds,
    sum(sla.response_samples) response_sla_samples,
    sumIf(sla.response_breaches,sla.response_samples>0) response_sla_breaches,
    toFloat64(sumIf(sla.response_deviation,sla.response_samples>0)) response_deviation,
    sum(sla.resolution_samples) resolution_sla_samples,
    sumIf(sla.resolution_breaches,sla.resolution_samples>0) resolution_sla_breaches,
    toFloat64(sumIf(sla.resolution_deviation,sla.resolution_samples>0)) resolution_deviation,
    countIf(rating BETWEEN 1 AND 5) feedback_count,
    sumIf(rating,rating BETWEEN 1 AND 5) rating_sum,
    countIf(rating>=4 AND rating<=5) positive_ratings,
    countIf(rating BETWEEN 1 AND 5 AND resolved) resolved_ratings
FROM tickets LEFT JOIN sla USING(ticket_id)
WHERE created_at>toDateTime64(0,3) AND department_id!='' AND %s
GROUP BY department_id ORDER BY department_id`

func (r *AnalyticsRepoStruct) DepartmentPerformance(ctx context.Context, filter models.Filter) (models.DepartmentPerformanceReport, error) {
	where, args := buildTimeFilter(filter, "created_at")

	if filter.DepartmentID != nil {
		where += " AND department_id=?"
		args = append(args, *filter.DepartmentID)
	}

	rows, err := r.db.Query(ctx, formatDepartmentQuery(where), args...)

	if err != nil {
		return models.DepartmentPerformanceReport{}, err
	}

	defer rows.Close()

	report := models.DepartmentPerformanceReport{Departments: make([]models.DepartmentPerformance, 0)}
	var organization departmentStats
	for rows.Next() {
		var item departmentStats

		if err = scanDepartmentStats(rows, &item); err != nil {
			return report, err
		}

		item.calculate()
		report.Departments = append(report.Departments, item.DepartmentPerformance)
		organization.add(item)
	}

	if err = rows.Err(); err != nil {
		return report, err
	}

	organization.calculate()
	report.Organization = organization.DepartmentPerformance
	return report, nil
}

func formatDepartmentQuery(where string) string {
	return strings.Replace(departmentPerformanceQuery, "%s", where, 1)
}

func scanDepartmentStats(row driver.Rows, value *departmentStats) error {
	return row.Scan(
		&value.DepartmentID, &value.Created, &value.Completed, &value.Canceled, &value.Active,
		&value.responseCount, &value.responseSeconds, &value.resolutionCount, &value.resolutionSeconds,
		&value.ResponseSLASampleCount, &value.ResponseSLABreaches, &value.responseDeviation,
		&value.ResolutionSLASampleCount, &value.ResolutionSLABreaches, &value.resolutionDeviation,
		&value.FeedbackCount, &value.ratingSum, &value.positiveRatings, &value.resolvedRatings,
	)
}

func (value *departmentStats) calculate() {
	value.ResponseSampleCount = value.responseCount
	value.ResolutionSampleCount = value.resolutionCount
	value.CompletionRate = percent(value.Completed, value.Created)
	value.AverageResponseSeconds = average(value.responseSeconds, value.responseCount)
	value.AverageResolutionSeconds = average(value.resolutionSeconds, value.resolutionCount)
	value.AverageResponseSLADeviationSeconds = average(value.responseDeviation, value.ResponseSLASampleCount)
	value.AverageResolutionSLADeviationSeconds = average(value.resolutionDeviation, value.ResolutionSLASampleCount)
	value.AverageRating = average(float64(value.ratingSum), value.FeedbackCount)
	value.PositiveRatingRate = percent(value.positiveRatings, value.FeedbackCount)
	value.ResolvedFeedbackRate = percent(value.resolvedRatings, value.FeedbackCount)
	value.FeedbackResponseRate = percent(value.FeedbackCount, value.Completed)
}

func (value *departmentStats) add(item departmentStats) {
	value.Created += item.Created
	value.Completed += item.Completed
	value.Canceled += item.Canceled
	value.Active += item.Active
	value.responseCount += item.responseCount
	value.responseSeconds += item.responseSeconds
	value.resolutionCount += item.resolutionCount
	value.resolutionSeconds += item.resolutionSeconds
	value.ResponseSLASampleCount += item.ResponseSLASampleCount
	value.ResponseSLABreaches += item.ResponseSLABreaches
	value.responseDeviation += item.responseDeviation
	value.ResolutionSLASampleCount += item.ResolutionSLASampleCount
	value.ResolutionSLABreaches += item.ResolutionSLABreaches
	value.resolutionDeviation += item.resolutionDeviation
	value.FeedbackCount += item.FeedbackCount
	value.ratingSum += item.ratingSum
	value.positiveRatings += item.positiveRatings
	value.resolvedRatings += item.resolvedRatings
}

func percent(part, total uint64) float64 {
	if total == 0 {
		return 0
	}

	return float64(part) / float64(total) * 100
}

func average(total float64, count uint64) float64 {
	if count == 0 {
		return 0
	}

	return total / float64(count)
}
