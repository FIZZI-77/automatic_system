package models

import "time"

type AnalyticsFilter struct {
	From           *time.Time `json:"from,omitempty"`
	To             *time.Time `json:"to,omitempty"`
	DepartmentID   *string    `json:"department_id,omitempty" binding:"omitempty,uuid"`
	CategoryID     *string    `json:"category_id,omitempty" binding:"omitempty,uuid"`
	Priority       *string    `json:"priority,omitempty"`
	BrigadeID      *string    `json:"brigade_id,omitempty" binding:"omitempty,uuid"`
	AssignmentMode *string    `json:"assignment_mode,omitempty" binding:"omitempty,oneof=MANUAL AUTOMATIC manual automatic"`
	FailureCode    *string    `json:"failure_code,omitempty"`
	Success        *bool      `json:"success,omitempty"`
}
type AnalyticsRequest struct {
	Filter *AnalyticsFilter `json:"filter,omitempty"`
}
type OperationalLatencyRequest struct {
	Filter  *AnalyticsFilter `json:"filter,omitempty"`
	GroupBy string           `json:"group_by,omitempty" binding:"omitempty,oneof=department category priority assignment_mode brigade engine travel_mode success failure_code"`
}
type AnalyticsBreakdownRequest struct {
	Filter    *AnalyticsFilter `json:"filter,omitempty"`
	Dimension string           `json:"dimension" binding:"required,oneof=department category priority status"`
	Limit     int32            `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
}
type AssetAnalyticsRequest struct {
	Filter    *AnalyticsFilter `json:"filter,omitempty"`
	AssetType *string          `json:"asset_type,omitempty"`
	District  *string          `json:"district,omitempty"`
}
