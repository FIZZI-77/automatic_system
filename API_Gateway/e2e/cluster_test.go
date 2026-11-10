package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestAPICluster запускает внешний E2E-набор против уже работающего Kubernetes-кластера.
// По умолчанию тест пропускается, чтобы обычный go test ./... не зависел от kubectl.
func TestAPICluster(t *testing.T) {
	if os.Getenv("API_GATEWAY_E2E") != "1" {
		t.Skip("установите API_GATEWAY_E2E=1 для запуска кластерного E2E")
	}
	if runtime.GOOS != "windows" {
		t.Skip("кластерный launcher пока использует PowerShell/kubectl из Windows workspace")
	}

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	launcher := filepath.Join(repoRoot, "scripts", "run-api-gateway-e2e.ps1")
	arguments := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", launcher, "-SkipSeed"}
	if os.Getenv("API_GATEWAY_E2E_SMTP") == "1" {
		arguments = append(arguments, "-IncludeSMTP")
	}
	cmd := exec.Command("powershell.exe", arguments...)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "E2E_API_ONLY=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("API Gateway cluster E2E failed: %v", err)
	}
}
