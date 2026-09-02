package bottleneck

import "testing"

func TestDetect(t *testing.T) {
	t.Parallel()
	got := Detect([]Evidence{{Component: "ticket", Utilization: .3, Available: true}, {Component: "valhalla", Utilization: .92, Available: true}, {Component: "postgres", Utilization: .4, Available: true}})
	if got.Component != "valhalla" || got.Confidence != "HIGH" {
		t.Errorf("Detect(evidence) = %+v, want valhalla HIGH", got)
	}
}
func TestDetectUnknown(t *testing.T) {
	t.Parallel()
	got := Detect(nil)
	if got.Component != "unknown" || got.Confidence != "LOW" {
		t.Errorf("Detect(nil) = %+v, want unknown LOW", got)
	}
}
