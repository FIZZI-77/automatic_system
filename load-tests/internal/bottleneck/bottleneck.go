package bottleneck

import "sort"

type Evidence struct {
	Component   string  `json:"component" yaml:"component"`
	Utilization float64 `json:"utilization" yaml:"utilization"`
	Growing     bool    `json:"growing" yaml:"growing"`
	Available   bool    `json:"available" yaml:"available"`
	Detail      string  `json:"detail,omitempty" yaml:"detail,omitempty"`
}
type Result struct {
	Component  string     `json:"component"`
	Reason     string     `json:"reason"`
	Confidence string     `json:"confidence"`
	Evidence   []Evidence `json:"evidence"`
}

func Detect(values []Evidence) Result {
	available := make([]Evidence, 0, len(values))
	for _, value := range values {
		if value.Available {
			available = append(available, value)
		}
	}
	if len(available) == 0 {
		return Result{Component: "unknown", Reason: "no confirmed metrics", Confidence: "LOW", Evidence: []Evidence{}}
	}
	sort.SliceStable(available, func(i, j int) bool {
		left, right := available[i].Utilization, available[j].Utilization
		if available[i].Growing {
			left += .25
		}
		if available[j].Growing {
			right += .25
		}
		return left > right
	})
	top := available[0]
	confidence := "MEDIUM"
	if top.Utilization >= .85 || top.Growing {
		confidence = "HIGH"
	}
	if len(available) < 3 {
		confidence = "LOW"
	}
	reason := top.Detail
	if reason == "" {
		reason = "highest measured utilization"
		if top.Growing {
			reason = "backlog or lag is growing"
		}
	}
	return Result{Component: top.Component, Reason: reason, Confidence: confidence, Evidence: available}
}
