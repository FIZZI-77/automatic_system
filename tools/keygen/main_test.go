package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritePEMCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.pem")
	if err := writePEM(path, "PRIVATE KEY", []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatalf("writePEM() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat generated key: %v", err)
	}
	if info.IsDir() {
		t.Fatal("generated key is a directory")
	}
	if info.Size() == 0 {
		t.Fatal("generated key is empty")
	}
}
