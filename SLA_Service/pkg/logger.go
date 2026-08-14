package pkg

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"strings"
)

func NewLogger() (*zap.Logger, error) {
	c := zap.NewProductionConfig()
	c.InitialFields = map[string]any{"service": "sla"}
	if strings.EqualFold(os.Getenv("LOG_LEVEL"), "debug") {
		c.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	}
	return c.Build()
}
