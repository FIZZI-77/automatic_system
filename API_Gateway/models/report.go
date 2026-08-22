package models

type CreateReportRequest struct {
	Name   string           `json:"name" binding:"required,min=3,max=160"`
	Type   string           `json:"type" binding:"required,oneof=ticket_overview sla_summary ticket_breakdown daily_tickets"`
	Format string           `json:"format" binding:"required,oneof=pdf xlsx csv"`
	Filter *AnalyticsFilter `json:"filter,omitempty"`
}
type GetReportRequest struct {
	ReportID string `json:"report_id" binding:"required,uuid"`
}
type ListReportsRequest struct {
	Status *string `json:"status,omitempty" binding:"omitempty,oneof=pending processing completed failed canceled"`
	Limit  int32   `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset int32   `json:"offset,omitempty" binding:"omitempty,min=0"`
}
