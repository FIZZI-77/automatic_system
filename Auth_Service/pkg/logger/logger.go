package logger

import "go.uber.org/zap"

func NewLogger(serviceName string, env string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()

	cfg.Encoding = "json"

	cfg.InitialFields = map[string]interface{}{
		"service": serviceName,
		"env":     env,
	}

	c
}
