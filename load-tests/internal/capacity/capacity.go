package capacity

import (
	"errors"
	"fmt"
	"math"
	"sort"
)

var ErrInvalidInput = errors.New("invalid capacity input")

type Stage struct {
	Name                  string             `json:"name,omitempty" yaml:"name,omitempty"`
	Throughput            float64            `json:"throughput" yaml:"throughput"`
	AverageLatencyMS      float64            `json:"average_latency_ms,omitempty" yaml:"average_latency_ms,omitempty"`
	P50MS                 float64            `json:"p50_ms" yaml:"p50_ms"`
	P95MS                 float64            `json:"p95_ms" yaml:"p95_ms"`
	P99MS                 float64            `json:"p99_ms" yaml:"p99_ms"`
	ErrorRate             float64            `json:"error_rate" yaml:"error_rate"`
	CPU                   float64            `json:"cpu" yaml:"cpu"`
	Memory                float64            `json:"memory" yaml:"memory"`
	KafkaLagSlope         float64            `json:"kafka_lag_slope" yaml:"kafka_lag_slope"`
	QueueSlope            float64            `json:"queue_slope" yaml:"queue_slope"`
	PgBouncerWaitingSlope float64            `json:"pgbouncer_waiting_slope" yaml:"pgbouncer_waiting_slope"`
	BacklogSlopes         map[string]float64 `json:"backlog_slopes,omitempty" yaml:"backlog_slopes,omitempty"`
	OOMKills              int                `json:"oom_kills" yaml:"oom_kills"`
	Restarts              int                `json:"restarts" yaml:"restarts"`
	ObservedConcurrency   *float64           `json:"observed_concurrency,omitempty" yaml:"observed_concurrency,omitempty"`
	Measurement           bool               `json:"measurement" yaml:"measurement"`
}

type Thresholds struct {
	ErrorRateMax             float64 `json:"error_rate_max" yaml:"error_rate_max"`
	P95MS                    float64 `json:"p95_ms" yaml:"p95_ms"`
	P99MS                    float64 `json:"p99_ms" yaml:"p99_ms"`
	CPUTarget                float64 `json:"cpu_target" yaml:"cpu_target"`
	MemoryTarget             float64 `json:"memory_target" yaml:"memory_target"`
	KafkaLagSlopeMax         float64 `json:"kafka_lag_slope_max" yaml:"kafka_lag_slope_max"`
	QueueSlopeMax            float64 `json:"queue_slope_max" yaml:"queue_slope_max"`
	PgBouncerWaitingSlopeMax float64 `json:"pgbouncer_waiting_slope_max" yaml:"pgbouncer_waiting_slope_max"`
	BacklogSlopeMax          float64 `json:"backlog_slope_max" yaml:"backlog_slope_max"`
}

type StageAssessment struct {
	Stage       Stage    `json:"stage"`
	Sustainable bool     `json:"sustainable"`
	Violations  []string `json:"violations"`
}
type Knee struct {
	Stage       Stage   `json:"stage"`
	SlopeRatio  float64 `json:"slope_ratio"`
	Explanation string  `json:"explanation"`
}
type MixedResult struct {
	Throughput       float64            `json:"throughput"`
	LimitingResource string             `json:"limiting_resource"`
	Utilization      map[string]float64 `json:"utilization"`
}
type ScalingPoint struct {
	CPU        float64 `json:"cpu" yaml:"cpu"`
	Throughput float64 `json:"throughput" yaml:"throughput"`
}

func Assess(stage Stage, limits Thresholds) StageAssessment {
	violations := make([]string, 0)
	if !stage.Measurement {
		violations = append(violations, "not a measurement window")
	}
	if stage.ErrorRate > limits.ErrorRateMax {
		violations = append(violations, "error rate above threshold")
	}
	if stage.P95MS > limits.P95MS {
		violations = append(violations, "p95 above threshold")
	}
	if stage.P99MS > limits.P99MS {
		violations = append(violations, "p99 above threshold")
	}
	if stage.CPU > limits.CPUTarget {
		violations = append(violations, "CPU above target")
	}
	if stage.Memory > limits.MemoryTarget {
		violations = append(violations, "memory above target")
	}
	if stage.KafkaLagSlope > limits.KafkaLagSlopeMax {
		violations = append(violations, "Kafka lag is growing")
	}
	if stage.QueueSlope > limits.QueueSlopeMax {
		violations = append(violations, "queue is growing")
	}
	if stage.PgBouncerWaitingSlope > limits.PgBouncerWaitingSlopeMax {
		violations = append(violations, "PgBouncer waiting is growing")
	}
	for name, slope := range stage.BacklogSlopes {
		if slope > limits.BacklogSlopeMax {
			violations = append(violations, name+" backlog is growing")
		}
	}
	if stage.OOMKills > 0 {
		violations = append(violations, "OOM kill observed")
	}
	if stage.Restarts > 0 {
		violations = append(violations, "restart observed")
	}
	return StageAssessment{Stage: stage, Sustainable: len(violations) == 0, Violations: violations}
}

func Sustainable(stages []Stage, limits Thresholds) (Stage, bool) {
	var best Stage
	found := false
	for _, stage := range stages {
		if assessment := Assess(stage, limits); assessment.Sustainable && (!found || stage.Throughput > best.Throughput) {
			best, found = stage, true
		}
	}
	return best, found
}

func FailurePoint(stages []Stage, limits Thresholds) (Stage, bool) {
	for _, stage := range sortedStages(stages) {
		if stage.Measurement && !Assess(stage, limits).Sustainable {
			return stage, true
		}
	}
	return Stage{}, false
}

func KneePoint(stages []Stage, multiplier float64) (Knee, bool) {
	if len(stages) < 3 || multiplier <= 1 {
		return Knee{}, false
	}
	sorted := sortedStages(stages)
	previousSlope := 0.0
	for i := 1; i < len(sorted); i++ {
		deltaThroughput := sorted[i].Throughput - sorted[i-1].Throughput
		if deltaThroughput <= 0 {
			continue
		}
		slope := math.Max((sorted[i].P95MS-sorted[i-1].P95MS)/deltaThroughput, 0)
		if i > 1 && previousSlope > 0 {
			ratio := slope / previousSlope
			if ratio >= multiplier {
				return Knee{Stage: sorted[i], SlopeRatio: ratio, Explanation: fmt.Sprintf("knee at %.2f op/s because p95 slope increased %.2fx", sorted[i].Throughput, ratio)}, true
			}
		}
		if slope > 0 {
			previousSlope = slope
		}
	}
	return Knee{}, false
}

func Brigades(positionsPerSecond, intervalSeconds float64) float64 {
	return positionsPerSecond * intervalSeconds
}
func LittleLaw(throughputPerSecond, latencySeconds float64) float64 {
	return throughputPerSecond * latencySeconds
}
func Deliveries(eventsPerSecond, recipients, channels float64) float64 {
	return eventsPerSecond * recipients * channels
}
func Nominal(replicas int, perReplica float64) float64 {
	if replicas <= 0 || perReplica < 0 {
		return 0
	}
	return float64(replicas) * perReplica
}
func ThroughputPerCPU(throughput, usedCPU float64) (float64, error) {
	if throughput < 0 || usedCPU <= 0 {
		return 0, ErrInvalidInput
	}
	return throughput / usedCPU, nil
}
func NetworkMBPerSecond(mbitPerSecond float64) (float64, error) {
	if mbitPerSecond < 0 {
		return 0, ErrInvalidInput
	}
	return mbitPerSecond / 8, nil
}
func FileOpsCeiling(mbitPerSecond, averageFileMB float64) (float64, error) {
	network, err := NetworkMBPerSecond(mbitPerSecond)
	if err != nil || averageFileMB <= 0 {
		return 0, ErrInvalidInput
	}
	return network / averageFileMB, nil
}

func BusinessCapacity(capacities, demand map[string]float64) (float64, string, error) {
	if len(capacities) == 0 || len(demand) == 0 {
		return 0, "", ErrInvalidInput
	}
	best, limiting := math.Inf(1), ""
	for resource, units := range demand {
		resourceCapacity, ok := capacities[resource]
		if !ok || units <= 0 {
			continue
		}
		candidate := resourceCapacity / units
		if candidate < best {
			best, limiting = candidate, resource
		}
	}
	if math.IsInf(best, 1) {
		return 0, "", ErrInvalidInput
	}
	return best, limiting, nil
}

func MixedCapacity(capacities map[string]float64, shares map[string]float64, demand map[string]map[string]float64) (MixedResult, error) {
	if len(capacities) == 0 || len(shares) == 0 || len(demand) == 0 {
		return MixedResult{}, ErrInvalidInput
	}
	perResource := make(map[string]float64, len(capacities))
	best, limiting := math.Inf(1), ""
	for resource, resourceCapacity := range capacities {
		units := 0.0
		for scenario, share := range shares {
			if share < 0 {
				return MixedResult{}, ErrInvalidInput
			}
			units += share * demand[scenario][resource]
		}
		perResource[resource] = units
		if units <= 0 {
			continue
		}
		candidate := resourceCapacity / units
		if candidate < best {
			best, limiting = candidate, resource
		}
	}
	if math.IsInf(best, 1) {
		return MixedResult{}, ErrInvalidInput
	}
	utilization := make(map[string]float64, len(capacities))
	for resource, units := range perResource {
		if capacities[resource] > 0 {
			utilization[resource] = best * units / capacities[resource]
		}
	}
	return MixedResult{Throughput: best, LimitingResource: limiting, Utilization: utilization}, nil
}

func ActiveUsers(systemCapacity float64, intervals []float64) (float64, error) {
	if systemCapacity < 0 || len(intervals) == 0 {
		return 0, ErrInvalidInput
	}
	rate := 0.0
	for _, interval := range intervals {
		if interval <= 0 {
			return 0, ErrInvalidInput
		}
		rate += 1 / interval
	}
	return systemCapacity / rate, nil
}
func NPlusOne(replicas int, perReplica float64) (float64, bool) {
	if replicas <= 1 || perReplica < 0 {
		return 0, false
	}
	return float64(replicas-1) * perReplica, true
}
func ComponentCapacity(nominal float64, ceilings map[string]float64) (float64, string, error) {
	if nominal < 0 {
		return 0, "", ErrInvalidInput
	}
	best, limiting := nominal, "stateless replicas"
	for name, ceiling := range ceilings {
		if ceiling < 0 {
			return 0, "", ErrInvalidInput
		}
		if ceiling < best {
			best, limiting = ceiling, name
		}
	}
	return best, limiting, nil
}
func ScalingEfficiency(base, point ScalingPoint) (float64, error) {
	if base.CPU <= 0 || base.Throughput <= 0 || point.CPU <= 0 || point.Throughput < 0 {
		return 0, ErrInvalidInput
	}
	return point.Throughput / ((point.CPU / base.CPU) * base.Throughput), nil
}
func sortedStages(stages []Stage) []Stage {
	sorted := append([]Stage(nil), stages...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Throughput < sorted[j].Throughput })
	return sorted
}
