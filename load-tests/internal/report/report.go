package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/FIZZI-77/automatic_system/load-tests/internal/bottleneck"
	"github.com/FIZZI-77/automatic_system/load-tests/internal/capacity"
)

type Latency struct {
	P50MS float64 `json:"p50_ms"`
	P95MS float64 `json:"p95_ms"`
	P99MS float64 `json:"p99_ms"`
}
type Capacity struct {
	PerReplica *float64 `json:"per_replica"`
	Nominal    *float64 `json:"nominal"`
	NPlusOne   *float64 `json:"n_plus_1"`
}
type Derived struct {
	EstimatedActiveUsers *float64           `json:"estimated_active_users"`
	Brigades             map[string]float64 `json:"brigades"`
	LittleLawConcurrency *float64           `json:"little_law_concurrency"`
}
type Summary struct {
	RunID                 string             `json:"run_id"`
	Scenario              string             `json:"scenario"`
	GitSHA                string             `json:"git_sha"`
	Server                any                `json:"server"`
	SustainableThroughput *float64           `json:"sustainable_throughput"`
	KneePoint             *float64           `json:"knee_point"`
	FailurePoint          *float64           `json:"failure_point"`
	Latency               Latency            `json:"latency"`
	ErrorRate             float64            `json:"error_rate"`
	ResourceUsage         map[string]float64 `json:"resource_usage"`
	Bottleneck            bottleneck.Result  `json:"bottleneck"`
	Capacity              Capacity           `json:"capacity"`
	Derived               Derived            `json:"derived"`
	Measured              []capacity.Stage   `json:"measured"`
	Extrapolated          []Extrapolated     `json:"extrapolated"`
	Limitations           []string           `json:"limitations"`
}
type Extrapolated struct {
	Name       string  `json:"name"`
	Value      float64 `json:"value"`
	Confidence string  `json:"confidence"`
	Basis      string  `json:"basis"`
}

func WriteJSON(writer io.Writer, summary Summary) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		return fmt.Errorf("encode summary JSON: %w", err)
	}
	return nil
}
func WriteCSV(writer io.Writer, summary Summary) error {
	csvWriter := csv.NewWriter(writer)
	rows := [][]string{{"scenario", "sustainable", "knee", "failure", "p95_ms", "p99_ms", "bottleneck", "confidence"}, {summary.Scenario, optional(summary.SustainableThroughput), optional(summary.KneePoint), optional(summary.FailurePoint), strconv.FormatFloat(summary.Latency.P95MS, 'f', 3, 64), strconv.FormatFloat(summary.Latency.P99MS, 'f', 3, 64), summary.Bottleneck.Component, summary.Bottleneck.Confidence}}
	if err := csvWriter.WriteAll(rows); err != nil {
		return fmt.Errorf("encode summary CSV: %w", err)
	}
	return nil
}
func WriteMarkdown(writer io.Writer, summary Summary) error {
	sustainable := optional(summary.SustainableThroughput)
	text := fmt.Sprintf("# Automatic System Capacity Report\n\n## Capacity\n\n| Scenario | Sustainable | Knee | Failure | p95 | p99 | Bottleneck |\n|---|---:|---:|---:|---:|---:|---|\n| %s | %s | %s | %s | %.2f ms | %.2f ms | %s (%s) |\n\n## Confidence / Limitations\n\n", summary.Scenario, sustainable, optional(summary.KneePoint), optional(summary.FailurePoint), summary.Latency.P95MS, summary.Latency.P99MS, summary.Bottleneck.Component, summary.Bottleneck.Confidence)
	if len(summary.Limitations) == 0 {
		text += "- No limitations were recorded.\n"
	} else {
		for _, limitation := range summary.Limitations {
			text += "- " + limitation + "\n"
		}
	}
	text += "\nMeasured stages are listed in summary.json. Extrapolated values are separate and include confidence and basis.\n"
	if _, err := io.Copy(writer, strings.NewReader(text)); err != nil {
		return fmt.Errorf("write Markdown report: %w", err)
	}
	return nil
}
func optional(value *float64) string {
	if value == nil {
		return "N/A"
	}
	return strconv.FormatFloat(*value, 'f', 3, 64)
}
