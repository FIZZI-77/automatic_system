package pkg

import (
	"encoding/json"
	"go.uber.org/zap"
)

func NewLogger() (*zap.Logger, error) {
	rawJSON := []byte(`{
	  "level": "debug",
	  "encoding": "json",
	  "outputPaths": ["stdout", "/tmp/logs"],
	  "errorOutputPaths": ["stderr"],
	  "initialFields": {"jwt": "auth"},
	  "encoderConfig": {
	    "messageKey": "message",
	    "levelKey": "level",
	    "levelEncoder": "lowercase"
	  }
	}`)

	var cfg zap.Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		return nil, err
	}

	logger, err := cfg.Build(zap.AddCaller(), zap.AddCallerSkip(2))

	if err != nil {
		return nil, err
	}

	return logger, nil
}
