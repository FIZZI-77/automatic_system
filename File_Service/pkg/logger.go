package pkg

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger() (*zap.Logger, error) {
	level := zapcore.InfoLevel
	if err := level.Set(strings.ToLower(os.Getenv("LOG_LEVEL"))); err != nil && os.Getenv("LOG_LEVEL") != "" {
		return nil, err
	}

	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(level)
	config.InitialFields = map[string]any{"service": "file"}
	return config.Build(zap.AddCaller())
}
