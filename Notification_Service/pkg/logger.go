package pkg

import (
	"go.uber.org/zap"
)

func NewLogger() (*zap.Logger, error) {
	c := zap.NewProductionConfig()
	c.InitialFields = map[string]any{"service": "notification"}
	return c.Build()
}
