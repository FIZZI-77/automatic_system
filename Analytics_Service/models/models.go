package models

import "time"

type Event struct {
	ID, Type, Topic string
	Payload         map[string]any
	Timestamp       time.Time
}
type Filter struct {
	From, To                           *time.Time
	DepartmentID, CategoryID, Priority *string
}
type Overview struct {
	Created, Completed, Canceled, Active                     uint64
	CompletionRate, AvgResponseSeconds, AvgResolutionSeconds float64
}
type SLA struct {
	ResponseWarnings, ResponseBreaches, ResolutionWarnings, ResolutionBreaches, Completed uint64
	BreachRate                                                                            float64
}
type Breakdown struct {
	Key     string
	Count   uint64
	Percent float64
}
type Daily struct {
	Day                                       time.Time
	Created, Completed, Canceled, SLABreaches uint64
}
type AssetBreakdown struct {
	Key                                    string
	Incidents, Repeated, Repairs, Critical uint64
}
type AssetSummary struct {
	Created, Incidents, Repeated, Repairs, Inspections, Critical uint64
	ByType, ByDistrict                                           []AssetBreakdown
}
