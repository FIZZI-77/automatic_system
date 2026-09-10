package parser

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/FIZZI-77/automatic_system/load-tests/internal/capacity"
)

type k6Summary struct {
	Metrics map[string]struct {
		Values map[string]float64 `json:"values"`
	} `json:"metrics"`
}

func K6Summary(reader io.Reader, throughput float64) (capacity.Stage, error) {
	var summary k6Summary
	if err := json.NewDecoder(reader).Decode(&summary); err != nil {
		return capacity.Stage{}, fmt.Errorf("decode k6 summary: %w", err)
	}
	duration, ok := summary.Metrics["http_req_duration{phase:measurement}"]
	if !ok {
		duration, ok = summary.Metrics["http_req_duration"]
	}
	if !ok {
		return capacity.Stage{}, fmt.Errorf("decode k6 summary: http_req_duration metric is missing")
	}
	failedMetric, ok := summary.Metrics["http_req_failed{phase:measurement}"]
	if !ok {
		failedMetric = summary.Metrics["http_req_failed"]
	}
	failed := failedMetric.Values["rate"]
	return capacity.Stage{Throughput: throughput, AverageLatencyMS: duration.Values["avg"], P50MS: duration.Values["med"], P95MS: duration.Values["p(95)"], P99MS: duration.Values["p(99)"], ErrorRate: failed, Measurement: true}, nil
}
