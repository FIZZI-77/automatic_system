package config

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func Load() error {
	p := os.Getenv("CONFIG_FILE")
	if p == "" {
		p = "config.yaml"
	}
	v := viper.New()
	v.SetConfigFile(filepath.Clean(p))
	if e := v.ReadInConfig(); e != nil {
		return e
	}
	return flat("", v.AllSettings())
}
func flat(p string, m map[string]any) error {
	for k, v := range m {
		n := strings.Trim(p+"_"+k, "_")
		for _, s := range []string{"password", "secret", "database_url"} {
			if strings.Contains(n, s) {
				return fmt.Errorf("secret %s must be in env", n)
			}
		}
		if x, ok := v.(map[string]any); ok {
			if e := flat(n, x); e != nil {
				return e
			}
			continue
		}
		key := strings.ToUpper(n)
		if _, ok := os.LookupEnv(key); ok {
			continue
		}
		var raw string
		switch x := v.(type) {
		case []any:
			a := []string{}
			for _, z := range x {
				a = append(a, fmt.Sprint(z))
			}
			raw = strings.Join(a, ",")
		case bool:
			raw = strconv.FormatBool(x)
		default:
			raw = fmt.Sprint(x)
		}
		os.Setenv(key, raw)
	}
	return nil
}
