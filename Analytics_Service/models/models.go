package models

import "time"

// Event описывает событие event.
type Event struct {
	ID                 string
	Type               string
	Topic              string
	Payload            map[string]any
	Timestamp          time.Time
	Version            uint32
	ProjectionEligible bool
}
// Filter задаёт условия фильтрации.
type Filter struct {
	From           *time.Time
	To             *time.Time
	DepartmentID   *string
	CategoryID     *string
	Priority       *string
	BrigadeID      *string
	AssignmentMode *string
	FailureCode    *string
	Success        *bool
}
// Overview описывает доменную модель.
type Overview struct {
	Created              uint64
	Completed            uint64
	Canceled             uint64
	Active               uint64
	CompletionRate       float64
	AvgResponseSeconds   float64
	AvgResolutionSeconds float64
}
// SLA описывает доменную модель.
type SLA struct {
	ResponseWarnings   uint64
	ResponseBreaches   uint64
	ResolutionWarnings uint64
	ResolutionBreaches uint64
	Completed          uint64
	BreachRate         float64
}
// Breakdown описывает доменную модель.
type Breakdown struct {
	Key     string
	Count   uint64
	Percent float64
}
// Daily описывает доменную модель.
type Daily struct {
	Day         time.Time
	Created     uint64
	Completed   uint64
	Canceled    uint64
	SLABreaches uint64
}
// AssetBreakdown описывает доменную модель.
type AssetBreakdown struct {
	Key       string
	Incidents uint64
	Repeated  uint64
	Repairs   uint64
	Critical  uint64
}
// AssetSummary описывает доменную модель.
type AssetSummary struct {
	Created     uint64
	Incidents   uint64
	Repeated    uint64
	Repairs     uint64
	Inspections uint64
	Critical    uint64
	ByType      []AssetBreakdown
	ByDistrict  []AssetBreakdown
}

// LatencyDistribution описывает доменную модель.
type LatencyDistribution struct {
	SampleCount    uint64
	AverageSeconds float64
	MedianSeconds  float64
	P90Seconds     float64
	P95Seconds     float64
	P99Seconds     float64
}

// OperationalLatency описывает доменную модель.
type OperationalLatency struct {
	AssignmentTime         LatencyDistribution
	RoutingCalculationTime LatencyDistribution
	Groups                 []OperationalLatencyGroup
}

// OperationalLatencyGroup описывает доменную модель.
type OperationalLatencyGroup struct {
	Dimension              string
	Key                    string
	AssignmentTime         LatencyDistribution
	RoutingCalculationTime LatencyDistribution
}

// DispatchFailureBreakdown описывает доменную модель.
type DispatchFailureBreakdown struct {
	Key     string
	Count   uint64
	Percent float64
}

// DispatchFailureReasonSummary описывает доменную модель.
type DispatchFailureReasonSummary struct {
	Reason      string
	Count       uint64
	RequestRate float64
}

// DispatchFailureReasonDimension описывает доменную модель.
type DispatchFailureReasonDimension struct {
	Reason        string
	Key           string
	Count         uint64
	ReasonPercent float64
}

// DispatchFailureSummary описывает доменную модель.
type DispatchFailureSummary struct {
	Requested           uint64
	Failed              uint64
	Expired             uint64
	Canceled            uint64
	FailureRate         float64
	ByStage             []DispatchFailureBreakdown
	ByCode              []DispatchFailureBreakdown
	BusinessReasons     []DispatchFailureReasonSummary
	ReasonsByDepartment []DispatchFailureReasonDimension
	ReasonsByCategory   []DispatchFailureReasonDimension
}

// BrigadeWorkloadItem описывает доменную модель.
type BrigadeWorkloadItem struct {
	BrigadeID string
	Incoming  uint64
	Assigned  uint64
	Completed uint64
	Active    uint64
}

// BrigadeWorkload описывает доменную модель.
type BrigadeWorkload struct {
	Incoming               uint64
	Assigned               uint64
	Completed              uint64
	Active                 uint64
	UnassignedBacklog      uint64
	BrigadeCount           uint64
	MaxActive              uint64
	AverageActive          float64
	StandardDeviation      float64
	CoefficientOfVariation float64
	Gini                   float64
	Brigades               []BrigadeWorkloadItem
}

// ActiveWorkerGroup описывает доменную модель.
type ActiveWorkerGroup struct {
	Dimension     string
	Key           string
	ActiveMembers uint64
	Available     uint64
	OnShift       uint64
}

// ActiveWorkers описывает доменную модель.
type ActiveWorkers struct {
	ActiveMembers uint64
	Available     uint64
	OnShift       uint64
	ByDepartment  []ActiveWorkerGroup
	ByBrigade     []ActiveWorkerGroup
}

// AssignmentFunnelStage описывает доменную модель.
type AssignmentFunnelStage struct {
	Stage                  string
	Count                  uint64
	ConversionFromPrevious float64
	TransitionTime         LatencyDistribution
}

// AssignmentFunnel описывает доменную модель.
type AssignmentFunnel struct {
	Stages []AssignmentFunnelStage
}

// DispatchModeEffectiveness описывает доменную модель.
type DispatchModeEffectiveness struct {
	Mode           string
	Requested      uint64
	Assigned       uint64
	SuccessRate    float64
	AssignmentTime LatencyDistribution
}

// DispatchEffectiveness описывает доменную модель.
type DispatchEffectiveness struct {
	Automatic                   DispatchModeEffectiveness
	Manual                      DispatchModeEffectiveness
	ManualReassignmentAvailable bool
}

// QueueAgeBucket описывает доменную модель.
type QueueAgeBucket struct {
	Range string
	Count uint64
}

// QueueAgeSummary описывает доменную модель.
type QueueAgeSummary struct {
	ActiveUnassigned uint64
	Age              LatencyDistribution
	Buckets          []QueueAgeBucket
}

// RoutingEfficiency описывает доменную модель.
type RoutingEfficiency struct {
	Routes                       uint64
	Recalculations               uint64
	Cancellations                uint64
	UnreachableCandidateRate     float64
	AverageDistanceKM            float64
	KilometersPerCompletedTicket float64
	ETASampleCount               uint64
	ETAMeanAbsoluteErrorSeconds  float64
	ETABiasSeconds               float64
	ETAP95AbsoluteErrorSeconds   float64
	ETAWithinFiveMinutesRate     float64
}

// CapacityForecast описывает доменную модель.
type CapacityForecast struct {
	ObservedDays         uint32
	AverageDailyIncoming float64
	ForecastNextDay      float64
	PeakHourlyIncoming   float64
	RequiredBrigades     uint64
	Formula              string
}

// OperationalInsights описывает доменную модель.
type OperationalInsights struct {
	DepartureTime    LatencyDistribution
	QueueAge         QueueAgeSummary
	Routing          RoutingEfficiency
	CapacityForecast CapacityForecast
}

// ProjectionTopicHealth описывает доменную модель.
type ProjectionTopicHealth struct {
	Topic                  string
	TotalEvents            uint64
	UnknownVersionEvents   uint64
	ProjectionEligibleRate float64
	LastOccurredAt         time.Time
	LastIngestedAt         time.Time
	FreshnessSeconds       float64
	IngestionP95Seconds    float64
}

// ProjectionHealth описывает доменную модель.
type ProjectionHealth struct {
	TotalEvents             uint64
	UnknownVersionEvents    uint64
	ProjectedEvents         uint64
	MissingProjectionEvents uint64
	ProjectionEligibleRate  float64
	ProjectionErrorRate     float64
	LastOccurredAt          time.Time
	LastIngestedAt          time.Time
	FreshnessSeconds        float64
	IngestionP95Seconds     float64
	Topics                  []ProjectionTopicHealth
}

// DispatchOperationItem описывает доменную модель.
type DispatchOperationItem struct {
	OperationID    string
	TicketID       string
	DepartmentID   string
	CategoryID     string
	BrigadeID      string
	AssignmentMode string
	Status         string
	FailureCode    string
	FailureStage   string
	TraceID        string
	RequestedAt    time.Time
	UpdatedAt      time.Time
}

// BrigadePerformanceItem описывает доменную модель.
type BrigadePerformanceItem struct {
	BrigadeID            string
	Completed            uint64
	ExecutionTime        LatencyDistribution
	SLABreaches          uint64
	SLABreachRate        float64
	RepeatedAssetTickets uint64
	ShiftCount           uint64
	ShiftHours           float64
	BusyHours            float64
	AverageParallelTasks float64
	CompletedPerShift    float64
	UtilizationRate      float64
}

// BrigadePerformance описывает доменную модель.
type BrigadePerformance struct {
	Completed             uint64
	SLABreaches           uint64
	RepeatedAssetTickets  uint64
	ExecutionTime         LatencyDistribution
	SLABreachRate         float64
	ShiftMetricsAvailable bool
	ShiftCount            uint64
	ShiftHours            float64
	BusyHours             float64
	AverageParallelTasks  float64
	CompletedPerShift     float64
	UtilizationRate       float64
	Brigades              []BrigadePerformanceItem
}
