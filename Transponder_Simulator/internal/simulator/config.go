package simulator

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	VehicleID      string
	BrigadeID      string
	DeviceID       string
	TargetURL      string
	APIKey         string
	RouteFile      string
	Interval       time.Duration
	RequestTimeout time.Duration
	RetryCount     int
	LoopRoute      bool
	DefaultSpeed   float64
	AccuracyMeters float64
}

func LoadConfig() (Config, error) {
	cfg := Config{
		VehicleID:      strings.TrimSpace(os.Getenv("VEHICLE_ID")),
		BrigadeID:      strings.TrimSpace(os.Getenv("BRIGADE_ID")),
		DeviceID:       strings.TrimSpace(os.Getenv("DEVICE_ID")),
		TargetURL:      strings.TrimSpace(os.Getenv("TARGET_URL")),
		APIKey:         strings.TrimSpace(os.Getenv("TRANSPONDER_API_KEY")),
		RouteFile:      envOrDefault("ROUTE_FILE", "routes/moscow-center.json"),
		Interval:       durationEnv("SEND_INTERVAL", 2*time.Second),
		RequestTimeout: durationEnv("REQUEST_TIMEOUT", 5*time.Second),
		RetryCount:     intEnv("RETRY_COUNT", 3),
		LoopRoute:      boolEnv("LOOP_ROUTE", true),
		DefaultSpeed:   floatEnv("DEFAULT_SPEED_KMH", 35),
		AccuracyMeters: floatEnv("GPS_ACCURACY_METERS", 5),
	}

	if cfg.VehicleID == "" {
		return Config{}, errors.New("VEHICLE_ID is required")
	}
	if cfg.BrigadeID == "" {
		return Config{}, errors.New("BRIGADE_ID is required")
	}
	if cfg.DeviceID == "" {
		cfg.DeviceID = "simulator-" + cfg.VehicleID
	}
	if cfg.Interval <= 0 {
		return Config{}, errors.New("SEND_INTERVAL must be positive")
	}
	if cfg.RequestTimeout <= 0 {
		return Config{}, errors.New("REQUEST_TIMEOUT must be positive")
	}
	if cfg.RetryCount < 0 {
		return Config{}, errors.New("RETRY_COUNT cannot be negative")
	}
	if cfg.DefaultSpeed < 0 {
		return Config{}, errors.New("DEFAULT_SPEED_KMH cannot be negative")
	}
	if cfg.AccuracyMeters < 0 {
		return Config{}, errors.New("GPS_ACCURACY_METERS cannot be negative")
	}
	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func intEnv(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func floatEnv(key string, fallback float64) float64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func boolEnv(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func (c Config) String() string {
	mode := "stdout"
	if c.TargetURL != "" {
		mode = c.TargetURL
	}
	return fmt.Sprintf("vehicle=%s brigade=%s device=%s target=%s interval=%s", c.VehicleID, c.BrigadeID, c.DeviceID, mode, c.Interval)
}
