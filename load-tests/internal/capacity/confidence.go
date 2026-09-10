package capacity

type ExtrapolationEvidence struct {
	MeasuredPoints     int
	MinEfficiency      float64
	SameBottleneck     bool
	DownstreamHeadroom float64
	TargetScale        float64
}

func ExtrapolationConfidence(e ExtrapolationEvidence) string {
	if e.MeasuredPoints >= 3 && e.MinEfficiency >= .85 && e.SameBottleneck && e.DownstreamHeadroom >= .2 && e.TargetScale <= 2 {
		return "HIGH"
	}
	if e.MeasuredPoints >= 2 && e.MinEfficiency >= .65 && e.TargetScale <= 4 {
		return "MEDIUM"
	}
	return "LOW"
}
