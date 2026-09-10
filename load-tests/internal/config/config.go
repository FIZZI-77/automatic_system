package config

import (
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/FIZZI-77/automatic_system/load-tests/internal/capacity"
	metricspkg "github.com/FIZZI-77/automatic_system/load-tests/internal/metrics"
)

type ServerProfile struct {
	Server struct {
		Name      string  `yaml:"name" json:"name"`
		CPUCores  float64 `yaml:"cpu_cores" json:"cpu_cores"`
		MemoryGiB float64 `yaml:"memory_gib" json:"memory_gib"`
		Disk      Disk    `yaml:"disk" json:"disk"`
		Network   Network `yaml:"network" json:"network"`
	} `yaml:"server" json:"server"`
	Reserved struct {
		CPUCores  float64 `yaml:"cpu_cores" json:"cpu_cores"`
		MemoryGiB float64 `yaml:"memory_gib" json:"memory_gib"`
	} `yaml:"reserved" json:"reserved"`
	Components map[string]Component `yaml:"components" json:"components"`
}
type Disk struct {
	Type      string  `yaml:"type" json:"type"`
	ReadMBPS  float64 `yaml:"read_mb_s" json:"read_mb_s"`
	WriteMBPS float64 `yaml:"write_mb_s" json:"write_mb_s"`
	ReadIOPS  float64 `yaml:"read_iops" json:"read_iops"`
	WriteIOPS float64 `yaml:"write_iops" json:"write_iops"`
}
type Network struct {
	DownloadMbps float64 `yaml:"download_mbps" json:"download_mbps"`
	UploadMbps   float64 `yaml:"upload_mbps" json:"upload_mbps"`
}
type Component struct {
	Replicas         int  `yaml:"replicas" json:"replicas"`
	CPURequestM      int  `yaml:"cpu_request_m" json:"cpu_request_m"`
	CPULimitM        int  `yaml:"cpu_limit_m" json:"cpu_limit_m"`
	MemoryRequestMiB int  `yaml:"memory_request_mib" json:"memory_request_mib"`
	MemoryLimitMiB   int  `yaml:"memory_limit_mib" json:"memory_limit_mib"`
	Stateful         bool `yaml:"stateful" json:"stateful"`
}

type ThresholdFile struct {
	Defaults   capacity.Thresholds            `yaml:"defaults" json:"defaults"`
	Scenarios  map[string]capacity.Thresholds `yaml:"scenarios" json:"scenarios"`
	Regression Regression                     `yaml:"regression" json:"regression"`
}
type Regression struct {
	ThroughputDecreaseMax  float64 `yaml:"throughput_decrease_max" json:"throughput_decrease_max"`
	P95IncreaseMax         float64 `yaml:"p95_increase_max" json:"p95_increase_max"`
	P99IncreaseMax         float64 `yaml:"p99_increase_max" json:"p99_increase_max"`
	CPUPerOpIncreaseMax    float64 `yaml:"cpu_per_op_increase_max" json:"cpu_per_op_increase_max"`
	MemoryPerOpIncreaseMax float64 `yaml:"memory_per_op_increase_max" json:"memory_per_op_increase_max"`
}

type Workload struct {
	Stages             []LoadStage                   `yaml:"stages" json:"stages"`
	Mix                map[string]float64            `yaml:"mix" json:"mix"`
	UserActivity       map[string]Activity           `yaml:"user_activity" json:"user_activity"`
	TelemetryIntervals []float64                     `yaml:"telemetry_intervals" json:"telemetry_intervals"`
	Amplification      map[string]map[string]float64 `yaml:"amplification" json:"amplification"`
	ResourceCapacity   map[string]float64            `yaml:"resource_capacity" json:"resource_capacity"`
}
type LoadStage struct {
	Rate          float64 `yaml:"rate" json:"rate"`
	Warmup        string  `yaml:"warmup" json:"warmup"`
	Measurement   string  `yaml:"measurement" json:"measurement"`
	Stabilization string  `yaml:"stabilization" json:"stabilization"`
}
type Activity struct {
	EverySeconds float64 `yaml:"every_seconds" json:"every_seconds"`
}

type Environment struct {
	Name          string             `yaml:"name" json:"name"`
	GatewayURL    string             `yaml:"gateway_url" json:"gateway_url"`
	PrometheusURL string             `yaml:"prometheus_url" json:"prometheus_url"`
	Namespace     string             `yaml:"namespace" json:"namespace"`
	Production    bool               `yaml:"production" json:"production"`
	Queries       []metricspkg.Query `yaml:"queries" json:"queries"`
}

func Load(path string, destination any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("decode config %s: %w", path, err)
	}
	return nil
}

func ValidateDestructive(environment Environment, allowed bool) error {
	name := strings.ToLower(environment.Name + " " + environment.Namespace + " " + environment.GatewayURL)
	if environment.Production || strings.Contains(name, "prod") || strings.Contains(name, "production") {
		return fmt.Errorf("destructive load tests are forbidden for production")
	}
	if !allowed {
		return fmt.Errorf("destructive load test requires LOAD_TEST_ALLOW_DESTRUCTIVE=true")
	}
	if strings.TrimSpace(environment.Namespace) == "" {
		return fmt.Errorf("destructive load test requires an explicit namespace")
	}
	return nil
}
