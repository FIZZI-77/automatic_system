package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEnvironmentWins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("grpc_port: 5000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_FILE", path)
	t.Setenv("GRPC_PORT", "6000")
	if err := Load(); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("GRPC_PORT"); got != "6000" {
		t.Fatalf("got %s", got)
	}
}

func TestLoadRejectsSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("db_password: unsafe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_FILE", path)
	if err := Load(); err == nil || !strings.Contains(err.Error(), "must be provided through environment") {
		t.Fatalf("got %v", err)
	}
}
