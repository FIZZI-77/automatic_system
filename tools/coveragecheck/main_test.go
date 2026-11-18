package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunConfiguration(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	config := filepath.Join(dir, "gates.json")
	profile := filepath.Join(dir, "coverage.out")
	if err := os.WriteFile(config, []byte(`{"service":{"pkg":90},"empty":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, []byte("mode: atomic\npkg/a.go:1.1,2.1 1 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, module, config, profile string
		wantError                     bool
	}{
		{"valid", "service", config, profile, false},
		{"unknown module", "unknown", config, profile, true},
		{"empty module", "empty", config, profile, true},
		{"missing config", "service", config + ".missing", profile, true},
		{"missing profile", "service", config, profile + ".missing", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := run(tt.profile, tt.config, tt.module, io.Discard)
			if (err != nil) != tt.wantError {
				t.Fatalf("run(%q) = %v; want error=%v", tt.module, err, tt.wantError)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name, profile string
		minimum       float64
		wantError     bool
	}{
		{"exact threshold", "mode: atomic\npkg/a.go:1.1,2.1 9 1\npkg/a.go:3.1,4.1 1 0\n", 90, false},
		{"below threshold", "mode: atomic\npkg/a.go:1.1,2.1 89 1\npkg/a.go:3.1,4.1 11 0\n", 90, true},
		{"no rounded pass", "mode: count\npkg/a.go:1.1,2.1 8999 1\npkg/a.go:3.1,4.1 1001 0\n", 90, true},
		{"missing package", "mode: set\nother/a.go:1.1,2.1 10 1\n", 90, true},
		{"empty profile", "", 90, true},
		{"header only", "mode: set\n", 90, true},
		{"bad mode", "mode: bad\npkg/a.go:1.1,2.1 10 1\n", 90, true},
		{"bad record", "mode: set\nbad\n", 90, true},
		{"bad count", "mode: set\npkg/a.go:1.1,2.1 10 x\n", 90, true},
		{"negative count", "mode: set\npkg/a.go:1.1,2.1 10 -1\n", 90, true},
		{"negative statements", "mode: set\npkg/a.go:1.1,2.1 -1 1\n", 90, true},
		{"invalid threshold", "mode: set\npkg/a.go:1.1,2.1 10 1\n", 101, true},
		{"merge duplicate blocks", "mode: atomic\npkg/a.go:1.1,2.1 9 0\npkg/a.go:1.1,2.1 9 1\npkg/a.go:3.1,4.1 1 0\n", 90, false},
		{"conflicting duplicate", "mode: set\npkg/a.go:1.1,2.1 9 1\npkg/a.go:1.1,2.1 10 1\n", 90, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := check(strings.NewReader(tt.profile), map[string]float64{"pkg": tt.minimum}, io.Discard)
			if (err != nil) != tt.wantError {
				t.Fatalf("check(%q, %g) = %v; want error=%v", tt.profile, tt.minimum, err, tt.wantError)
			}
		})
	}
}
