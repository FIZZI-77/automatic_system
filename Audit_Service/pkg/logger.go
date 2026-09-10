package pkg

import "go.uber.org/zap"

func NewLogger() (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.InitialFields = map[string]any{"service": "audit"}
	return cfg.Build()
}
