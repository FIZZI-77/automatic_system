package pkg

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger() (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.InitialFields = map[string]any{"service": "routing"}
	cfg.EncoderConfig.MessageKey = "message"
	if raw := strings.TrimSpace(os.Getenv("LOG_LEVEL")); raw != "" {
		var level zapcore.Level
		if err := level.UnmarshalText([]byte(raw)); err != nil {
			return nil, err
		}
		cfg.Level = zap.NewAtomicLevelAt(level)
	}
	return cfg.Build(zap.AddCaller())
}
