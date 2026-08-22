package models

import "time"

type AnalyticsFilter struct {
	From         *time.Time `json:"from,omitempty"`
	To           *time.Time `json:"to,omitempty"`
	DepartmentID *string    `json:"department_id,omitempty" binding:"omitempty,uuid"`
	CategoryID   *string    `json:"category_id,omitempty" binding:"omitempty,uuid"`
	Priority     *string    `json:"priority,omitempty"`
}
type AnalyticsRequest struct {
	Filter *AnalyticsFilter `json:"filter,omitempty"`
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
