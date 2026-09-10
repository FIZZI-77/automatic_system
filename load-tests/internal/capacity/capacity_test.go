package capacity

import (
	"math"
	"testing"
)

func validStage(throughput, p95 float64) Stage {
	return Stage{Throughput: throughput, P95MS: p95, P99MS: p95 * 1.5, CPU: .5, Memory: .5, Measurement: true}
}
func limits() Thresholds {
	return Thresholds{ErrorRateMax: .001, P95MS: 500, P99MS: 1000, CPUTarget: .7, MemoryTarget: .8}
}

func TestSustainableAndFailurePoint(t *testing.T) {
	t.Parallel()
	stages := []Stage{validStage(100, 100), validStage(200, 200), validStage(300, 800)}
	got, ok := Sustainable(stages, limits())
	if !ok || got.Throughput != 200 {
		t.Errorf("Sustainable(stages) = %#v, %v, want throughput 200, true", got, ok)
	}
	failure, ok := FailurePoint(stages, limits())
	if !ok || failure.Throughput != 300 {
		t.Errorf("FailurePoint(stages) = %#v, %v, want throughput 300, true", failure, ok)
	}
}
func TestKneePoint(t *testing.T) {
	t.Parallel()
	stages := []Stage{validStage(100, 100), validStage(200, 120), validStage(300, 220)}
	got, ok := KneePoint(stages, 3)
	if !ok || got.Stage.Throughput != 300 || got.SlopeRatio != 5 {
		t.Errorf("KneePoint(stages, 3) = %#v, %v, want throughput 300 ratio 5", got, ok)
	}
}

func TestRequiredFormulas(t *testing.T) {
	t.Parallel()
	if got := Brigades(100, 5); got != 500 {
		t.Errorf("Brigades(100, 5) = %v, want 500", got)
	}
	if got := LittleLaw(20, .5); got != 10 {
		t.Errorf("LittleLaw(20, .5) = %v, want 10", got)
	}
	if got := Deliveries(100, 5, 2); got != 1000 {
		t.Errorf("Deliveries(100, 5, 2) = %v, want 1000", got)
	}
	if got := Nominal(3, 100); got != 300 {
		t.Errorf("Nominal(3, 100) = %v, want 300", got)
	}
	if got, ok := NPlusOne(3, 100); !ok || got != 200 {
		t.Errorf("NPlusOne(3, 100) = %v, %v, want 200, true", got, ok)
	}
	if got, err := ActiveUsers(100, []float64{10, 20}); err != nil || math.Abs(got-666.6666666666666) > 1e-9 {
		t.Errorf("ActiveUsers(100, [10,20]) = %v, %v, want approximately 666.67, nil", got, err)
	}
	if got, err := FileOpsCeiling(800, 10); err != nil || got != 10 {
		t.Errorf("FileOpsCeiling(800, 10) = %v, %v, want 10, nil", got, err)
	}
}

func TestBusinessAndMixedCapacity(t *testing.T) {
	t.Parallel()
	capacities := map[string]float64{"ticket": 3000, "routing": 300}
	got, limiting, err := BusinessCapacity(capacities, map[string]float64{"ticket": 3, "routing": 2})
	if err != nil || got != 150 || limiting != "routing" {
		t.Errorf("BusinessCapacity(...) = %v, %q, %v, want 150, routing, nil", got, limiting, err)
	}
	mixed, err := MixedCapacity(capacities, map[string]float64{"read": .75, "dispatch": .25}, map[string]map[string]float64{"read": {"ticket": 1}, "dispatch": {"ticket": 3, "routing": 2}})
	if err != nil || mixed.Throughput != 600 || mixed.LimitingResource != "routing" {
		t.Errorf("MixedCapacity(...) = %+v, %v, want throughput 600 limiting routing", mixed, err)
	}
}
func TestScalingAndComponentCapacity(t *testing.T) {
	t.Parallel()
	efficiency, err := ScalingEfficiency(ScalingPoint{CPU: .5, Throughput: 400}, ScalingPoint{CPU: 1, Throughput: 760})
	if err != nil || efficiency != .95 {
		t.Errorf("ScalingEfficiency(...) = %v, %v, want .95, nil", efficiency, err)
	}
	got, limiting, err := ComponentCapacity(1000, map[string]float64{"database": 700, "network": 900})
	if err != nil || got != 700 || limiting != "database" {
		t.Errorf("ComponentCapacity(...) = %v, %q, %v, want 700, database, nil", got, limiting, err)
	}
}
