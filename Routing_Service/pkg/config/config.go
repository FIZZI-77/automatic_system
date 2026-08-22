package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

var secretParts = []string{"password", "secret", "token", "api_key", "private_key", "access_key", "database_url", "dbstring"}

// Load reads non-secret settings from YAML and exposes them through the existing
// environment-based configuration boundary. Environment variables always win.
func Load() error {
	path := strings.TrimSpace(os.Getenv("CONFIG_FILE"))
	if path == "" {
		path = "config.yaml"
	}
	v := viper.New()
	v.SetConfigFile(filepath.Clean(path))
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return nil
		}
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read config %s: %w", path, err)
	}
	return flatten("", v.AllSettings())
}

func flatten(prefix string, values map[string]any) error {
	for key, value := range values {
		name := strings.ToLower(strings.Trim(strings.Join([]string{prefix, key}, "_"), "_"))
		for _, part := range secretParts {
			if strings.Contains(name, part) {
				return fmt.Errorf("secret %q must be provided through environment", name)
			}
		}
		if nested, ok := value.(map[string]any); ok {
			if err := flatten(name, nested); err != nil {
				return err
			}
			continue
		}
		envKey := strings.ToUpper(name)
		if _, exists := os.LookupEnv(envKey); exists {
			continue
		}
		var raw string
		switch item := value.(type) {
		case []any:
			parts := make([]string, 0, len(item))
			for _, x := range item {
				parts = append(parts, fmt.Sprint(x))
			}
			raw = strings.Join(parts, ",")
		case bool:
			raw = strconv.FormatBool(item)
		default:
			raw = fmt.Sprint(item)
		}
		if err := os.Setenv(envKey, raw); err != nil {
			return fmt.Errorf("set %s: %w", envKey, err)
		}
	}
	return nil
}
