package models

import "time"

type Event struct {
	ID, Type, Topic    string
	Payload            map[string]any
	Timestamp          time.Time
	Version            uint32
	ProjectionEligible bool
}
type Filter struct {
	From, To                           *time.Time
	DepartmentID, CategoryID, Priority *string
	BrigadeID, AssignmentMode          *string
	FailureCode                        *string
	Success                            *bool
}
type Overview struct {
	Created              uint64
	Completed            uint64
	Canceled             uint64
	Active               uint64
	CompletionRate       float64
	AvgResponseSeconds   float64
	AvgResolutionSeconds float64
}
type SLA struct {
	ResponseWarnings   uint64
	ResponseBreaches   uint64
	ResolutionWarnings uint64
	ResolutionBreaches uint64
	Completed          uint64
	BreachRate         float64
}
type Breakdown struct {
	Key     string
	Count   uint64
	Percent float64
}
type Daily struct {
	Day         time.Time
	Created     uint64
	Completed   uint64
	Canceled    uint64
	SLABreaches uint64
}
type AssetBreakdown struct {
	Key       string
	Incidents uint64
	Repeated  uint64
	Repairs   uint64
	Critical  uint64
}
type AssetSummary struct {
	Created            uint64
	Incidents          uint64
	Repeated           uint64
	Repairs            uint64
	Inspections        uint64
	Critical           uint64
	ByType, ByDistrict []AssetBreakdown
}

type LatencyDistribution struct {
	SampleCount            uint64
	AverageSeconds         float64
	MedianSeconds          float64
	P90Seconds             float64
	P95Seconds, P99Seconds float64
}

type OperationalLatency struct {
	AssignmentTime         LatencyDistribution
	RoutingCalculationTime LatencyDistribution
	Groups                 []OperationalLatencyGroup
}

type OperationalLatencyGroup struct {
	Dimension              string
	Key                    string
	AssignmentTime         LatencyDistribution
	RoutingCalculationTime LatencyDistribution
}

type DispatchFailureBreakdown struct {
	Key     string
	Count   uint64
	Percent float64
}

type DispatchFailureReasonSummary struct {
	Reason      string
	Count       uint64
	RequestRate float64
}

type DispatchFailureReasonDimension struct {
	Reason, Key   string
	Count         uint64
	ReasonPercent float64
}

type DispatchFailureSummary struct {
	Requested, Failed, Expired, Canceled uint64
	FailureRate                          float64
	ByStage, ByCode                      []DispatchFailureBreakdown
	BusinessReasons                      []DispatchFailureReasonSummary
	ReasonsByDepartment                  []DispatchFailureReasonDimension
	ReasonsByCategory                    []DispatchFailureReasonDimension
}

type BrigadeWorkloadItem struct {
	BrigadeID                     string
	Incoming, Assigned, Completed uint64
	Active                        uint64
}

type BrigadeWorkload struct {
	Incoming, Assigned, Completed uint64
	Active, UnassignedBacklog     uint64
	BrigadeCount, MaxActive       uint64
	AverageActive                 float64
	StandardDeviation             float64
	CoefficientOfVariation        float64
	Gini                          float64
	Brigades                      []BrigadeWorkloadItem
}

type ActiveWorkerGroup struct {
	Dimension, Key                    string
	ActiveMembers, Available, OnShift uint64
}

type ActiveWorkers struct {
	ActiveMembers, Available, OnShift uint64
	ByDepartment, ByBrigade           []ActiveWorkerGroup
}

type AssignmentFunnelStage struct {
	Stage                  string
	Count                  uint64
	ConversionFromPrevious float64
	TransitionTime         LatencyDistribution
}

type AssignmentFunnel struct {
	Stages []AssignmentFunnelStage
}

type DispatchModeEffectiveness struct {
	Mode           string
	Requested      uint64
	Assigned       uint64
	SuccessRate    float64
	AssignmentTime LatencyDistribution
}

type DispatchEffectiveness struct {
	Automatic                   DispatchModeEffectiveness
	Manual                      DispatchModeEffectiveness
	ManualReassignmentAvailable bool
}

type QueueAgeBucket struct {
	Range string
	Count uint64
}

type QueueAgeSummary struct {
	ActiveUnassigned uint64
	Age              LatencyDistribution
	Buckets          []QueueAgeBucket
}

type RoutingEfficiency struct {
	Routes, Recalculations, Cancellations uint64
	UnreachableCandidateRate              float64
	AverageDistanceKM                     float64
	KilometersPerCompletedTicket          float64
	ETASampleCount                        uint64
	ETAMeanAbsoluteErrorSeconds           float64
	ETABiasSeconds                        float64
	ETAP95AbsoluteErrorSeconds            float64
	ETAWithinFiveMinutesRate              float64
}

type CapacityForecast struct {
	ObservedDays                          uint32
	AverageDailyIncoming, ForecastNextDay float64
	PeakHourlyIncoming                    float64
	RequiredBrigades                      uint64
	Formula                               string
}

type OperationalInsights struct {
	DepartureTime    LatencyDistribution
	QueueAge         QueueAgeSummary
	Routing          RoutingEfficiency
	CapacityForecast CapacityForecast
}

type ProjectionTopicHealth struct {
	Topic                                 string
	TotalEvents, UnknownVersionEvents     uint64
	ProjectionEligibleRate                float64
	LastOccurredAt, LastIngestedAt        time.Time
	FreshnessSeconds, IngestionP95Seconds float64
}

type ProjectionHealth struct {
	TotalEvents, UnknownVersionEvents           uint64
	ProjectedEvents, MissingProjectionEvents    uint64
	ProjectionEligibleRate, ProjectionErrorRate float64
	LastOccurredAt, LastIngestedAt              time.Time
	FreshnessSeconds, IngestionP95Seconds       float64
	Topics                                      []ProjectionTopicHealth
}

type DispatchOperationItem struct {
	OperationID, TicketID, DepartmentID, CategoryID string
	BrigadeID, AssignmentMode, Status               string
	FailureCode, FailureStage, TraceID              string
	RequestedAt, UpdatedAt                          time.Time
}

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

type BrigadePerformance struct {
	Completed, SLABreaches, RepeatedAssetTickets uint64
	ExecutionTime                                LatencyDistribution
	SLABreachRate                                float64
	ShiftMetricsAvailable                        bool
	ShiftCount                                   uint64
	ShiftHours, BusyHours, AverageParallelTasks  float64
	CompletedPerShift, UtilizationRate           float64
	Brigades                                     []BrigadePerformanceItem
}
