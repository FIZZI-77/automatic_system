package config

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var secret = []string{"password", "secret", "token", "api_key", "private_key", "access_key", "database_url", "dbstring"}

func Load() error {
	path := strings.TrimSpace(os.Getenv("CONFIG_FILE"))
	if path == "" {
		path = "config.yaml"
	}
	v := viper.New()
	v.SetConfigFile(filepath.Clean(path))
	if e := v.ReadInConfig(); e != nil {
		return fmt.Errorf("read config: %w", e)
	}
	return flatten("", v.AllSettings())
}
func flatten(prefix string, m map[string]any) error {
	for k, v := range m {
		name := strings.ToLower(strings.Trim(prefix+"_"+k, "_"))
		for _, x := range secret {
			if strings.Contains(name, x) {
				return fmt.Errorf("secret %q must be provided through environment", name)
			}
		}
		if nested, ok := v.(map[string]any); ok {
			if e := flatten(name, nested); e != nil {
				return e
			}
			continue
		}
		key := strings.ToUpper(name)
		if _, ok := os.LookupEnv(key); ok {
			continue
		}
		var raw string
		switch x := v.(type) {
		case []any:
			a := make([]string, len(x))
			for i, z := range x {
				a[i] = fmt.Sprint(z)
			}
			raw = strings.Join(a, ",")
		case bool:
			raw = strconv.FormatBool(x)
		default:
			raw = fmt.Sprint(x)
		}
		if e := os.Setenv(key, raw); e != nil {
			return e
		}
	}
	return nil
}
