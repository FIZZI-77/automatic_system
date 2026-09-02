package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/FIZZI-77/automatic_system/load-tests/internal/bottleneck"
	"github.com/FIZZI-77/automatic_system/load-tests/internal/capacity"
	configpkg "github.com/FIZZI-77/automatic_system/load-tests/internal/config"
	reportpkg "github.com/FIZZI-77/automatic_system/load-tests/internal/report"
)

type analysisInput struct {
	RunID              string                `json:"run_id"`
	Scenario           string                `json:"scenario"`
	GitSHA             string                `json:"git_sha"`
	Stages             []capacity.Stage      `json:"stages"`
	Thresholds         capacity.Thresholds   `json:"thresholds"`
	Evidence           []bottleneck.Evidence `json:"bottleneck_evidence"`
	Replicas           int                   `json:"replicas"`
	UserIntervals      []float64             `json:"user_intervals"`
	TelemetryIntervals []float64             `json:"telemetry_intervals"`
	Limitations        []string              `json:"limitations"`
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "automatic-capacity:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: automatic-capacity <run|analyze|report|compare|estimate> [options]")
	}
	switch args[0] {
	case "run":
		return runScenario(ctx, args[1:])
	case "analyze":
		return analyze(args[1:])
	case "report":
		return renderReport(args[1:])
	case "compare":
		return compare(args[1:])
	case "estimate":
		return estimate(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func analyze(args []string) error {
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	inputPath := flags.String("input", "", "analysis input JSON")
	outputDir := flags.String("output", "", "report directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" {
		return errors.New("analyze requires --input")
	}
	var input analysisInput
	if err := readJSON(*inputPath, &input); err != nil {
		return err
	}
	summary := buildSummary(input)
	directory := *outputDir
	if directory == "" {
		directory = filepath.Join("load-tests", "reports", input.RunID)
	}
	return writeReports(directory, summary)
}

func buildSummary(input analysisInput) reportpkg.Summary {
	summary := reportpkg.Summary{RunID: input.RunID, Scenario: input.Scenario, GitSHA: input.GitSHA, ResourceUsage: map[string]float64{}, Bottleneck: bottleneck.Detect(input.Evidence), Derived: reportpkg.Derived{Brigades: map[string]float64{}}, Measured: input.Stages, Extrapolated: []reportpkg.Extrapolated{}, Limitations: input.Limitations}
	if sustainable, ok := capacity.Sustainable(input.Stages, input.Thresholds); ok {
		value := sustainable.Throughput
		summary.SustainableThroughput = &value
		summary.Latency = reportpkg.Latency{P50MS: sustainable.P50MS, P95MS: sustainable.P95MS, P99MS: sustainable.P99MS}
		summary.ErrorRate = sustainable.ErrorRate
		summary.ResourceUsage["cpu"] = sustainable.CPU
		summary.ResourceUsage["memory"] = sustainable.Memory
		concurrency := capacity.LittleLaw(value, sustainable.AverageLatencyMS/1000)
		summary.Derived.LittleLawConcurrency = &concurrency
		if input.Replicas > 0 {
			perReplica := value / float64(input.Replicas)
			nominal := capacity.Nominal(input.Replicas, perReplica)
			summary.Capacity.PerReplica, summary.Capacity.Nominal = &perReplica, &nominal
			if n1, available := capacity.NPlusOne(input.Replicas, perReplica); available {
				summary.Capacity.NPlusOne = &n1
			}
		}
		if users, err := capacity.ActiveUsers(value, input.UserIntervals); err == nil {
			summary.Derived.EstimatedActiveUsers = &users
		}
		for _, interval := range input.TelemetryIntervals {
			summary.Derived.Brigades[strconv.FormatFloat(interval, 'f', -1, 64)+"s"] = capacity.Brigades(value, interval)
		}
	}
	if knee, ok := capacity.KneePoint(input.Stages, 2.5); ok {
		value := knee.Stage.Throughput
		summary.KneePoint = &value
	}
	if failure, ok := capacity.FailurePoint(input.Stages, input.Thresholds); ok {
		value := failure.Throughput
		summary.FailurePoint = &value
	}
	return summary
}

func renderReport(args []string) error {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	input := flags.String("input", "", "summary JSON")
	output := flags.String("output", "", "Markdown output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return errors.New("report requires --input")
	}
	var summary reportpkg.Summary
	if err := readJSON(*input, &summary); err != nil {
		return err
	}
	writer, closeWriter, err := outputWriter(*output)
	if err != nil {
		return err
	}
	defer closeWriter()
	return reportpkg.WriteMarkdown(writer, summary)
}

func compare(args []string) error {
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	baselinePath := flags.String("baseline", "", "baseline summary")
	currentPath := flags.String("current", "", "current summary")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *baselinePath == "" || *currentPath == "" {
		return errors.New("compare requires --baseline and --current")
	}
	var baseline, current reportpkg.Summary
	if err := readJSON(*baselinePath, &baseline); err != nil {
		return err
	}
	if err := readJSON(*currentPath, &current); err != nil {
		return err
	}
	result := map[string]any{"scenario": current.Scenario, "throughput_delta_percent": delta(baseline.SustainableThroughput, current.SustainableThroughput), "p95_delta_percent": percentDelta(baseline.Latency.P95MS, current.Latency.P95MS), "p99_delta_percent": percentDelta(baseline.Latency.P99MS, current.Latency.P99MS)}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func estimate(args []string) error {
	flags := flag.NewFlagSet("estimate", flag.ContinueOnError)
	resultPath := flags.String("result", "", "summary JSON")
	measuredServer := flags.String("measured-server", "", "measured server YAML")
	targetServer := flags.String("server", "", "target server YAML")
	efficiency := flags.Float64("efficiency", 0, "measured scaling efficiency")
	points := flags.Int("points", 0, "number of measured scaling points")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *resultPath == "" || *measuredServer == "" || *targetServer == "" {
		return errors.New("estimate requires --result, --measured-server and --server")
	}
	var summary reportpkg.Summary
	if err := readJSON(*resultPath, &summary); err != nil {
		return err
	}
	if summary.SustainableThroughput == nil {
		return errors.New("result has no measured sustainable throughput")
	}
	var measured, target configpkg.ServerProfile
	if err := configpkg.Load(*measuredServer, &measured); err != nil {
		return err
	}
	if err := configpkg.Load(*targetServer, &target); err != nil {
		return err
	}
	if *points < 2 || *efficiency <= 0 {
		return errors.New("insufficient measurements for reliable extrapolation")
	}
	ratio := target.Server.CPUCores / measured.Server.CPUCores
	if ratio <= 0 {
		return capacity.ErrInvalidInput
	}
	confidence := capacity.ExtrapolationConfidence(capacity.ExtrapolationEvidence{MeasuredPoints: *points, MinEfficiency: *efficiency, SameBottleneck: true, DownstreamHeadroom: .2, TargetScale: ratio})
	result := reportpkg.Extrapolated{Name: target.Server.Name, Value: *summary.SustainableThroughput * ratio * *efficiency, Confidence: confidence, Basis: fmt.Sprintf("CPU ratio %.3f x measured efficiency %.3f; stateful ceilings must be checked separately", ratio, *efficiency)}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func runScenario(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("run requires a scenario name")
	}
	scenario := args[0]
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	rate := flags.Int("rate", 10, "arrival rate")
	duration := flags.Duration("timeout", 2*time.Hour, "process timeout")
	baseURL := flags.String("base-url", "http://localhost:8081", "gateway URL")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	script, ok := scenarioScripts()[scenario]
	if !ok {
		return fmt.Errorf("scenario %q is not implemented", scenario)
	}
	runID := time.Now().UTC().Format("20060102T150405Z") + "-" + strings.ReplaceAll(scenario, "/", "-")
	if (scenario == "location" || scenario == "full") && os.Getenv("LOAD_TEST_ALLOW_DESTRUCTIVE") != "true" {
		return errors.New("write scenario requires LOAD_TEST_ALLOW_DESTRUCTIVE=true")
	}
	if strings.Contains(strings.ToLower(*baseURL), "prod") {
		return errors.New("production target is forbidden")
	}
	rawDirectory := filepath.Join("load-tests", "results", "raw", runID)
	if err := os.MkdirAll(rawDirectory, 0o755); err != nil {
		return fmt.Errorf("create raw result directory: %w", err)
	}
	runCtx, cancel := context.WithTimeout(ctx, *duration)
	defer cancel()
	summaryPath := filepath.Join(rawDirectory, "k6.json")
	command := exec.CommandContext(runCtx, "k6", "run", "--summary-export", summaryPath, "--env", "BASE_URL="+*baseURL, "--env", fmt.Sprintf("K6_RATE=%d", *rate), "--env", "K6_RUN_ID="+runID, script)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("run k6 scenario %s: %w", scenario, err)
	}
	metadata := map[string]any{"run_id": runID, "scenario": scenario, "base_url": *baseURL, "rate": *rate, "git_sha": gitSHA(ctx), "ended_at": time.Now().UTC()}
	file, err := os.Create(filepath.Join(rawDirectory, "config.json"))
	if err != nil {
		return fmt.Errorf("create run metadata: %w", err)
	}
	encodeErr := json.NewEncoder(file).Encode(metadata)
	closeErr := file.Close()
	if encodeErr != nil {
		return fmt.Errorf("encode run metadata: %w", encodeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close run metadata: %w", closeErr)
	}
	return nil
}

func gitSHA(ctx context.Context) string {
	output, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

func scenarioScripts() map[string]string {
	return map[string]string{"gateway": "load-tests/k6/gateway/baseline.js", "gateway-authenticated-read": "load-tests/k6/gateway/authenticated-read.js", "auth-login": "load-tests/k6/auth/login.js", "auth-refresh": "load-tests/k6/auth/refresh.js", "ticket-read": "load-tests/k6/ticket/read.js", "location": "load-tests/k6/location/steady.js", "dispatch-preview": "load-tests/k6/dispatch/preview.js", "analytics": "load-tests/k6/analytics/queries.js", "full": "load-tests/k6/full-system/mixed.js"}
}

func writeReports(directory string, summary reportpkg.Summary) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	writers := []struct {
		name  string
		write func(*os.File) error
	}{{"summary.json", func(file *os.File) error { return reportpkg.WriteJSON(file, summary) }}, {"summary.csv", func(file *os.File) error { return reportpkg.WriteCSV(file, summary) }}, {"report.md", func(file *os.File) error { return reportpkg.WriteMarkdown(file, summary) }}}
	for _, item := range writers {
		file, err := os.Create(filepath.Join(directory, item.name))
		if err != nil {
			return fmt.Errorf("create %s: %w", item.name, err)
		}
		writeErr := item.write(file)
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
func readJSON(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	if err := json.NewDecoder(file).Decode(destination); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
func outputWriter(path string) (*os.File, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, func() {}, err
	}
	return file, func() { _ = file.Close() }, nil
}
func delta(base, current *float64) any {
	if base == nil || current == nil || *base == 0 {
		return "N/A"
	}
	return percentDelta(*base, *current)
}
func percentDelta(base, current float64) any {
	if base == 0 {
		return "N/A"
	}
	return (current - base) / base * 100
}
