package service

import (
	"strings"
	"testing"
)

func TestNewIntegrationSecret(t *testing.T) {
	first, err := newIntegrationSecret()

	if err != nil {
		t.Fatalf("newIntegrationSecret() error = %v, want nil", err)
	}

	second, err := newIntegrationSecret()

	if err != nil {
		t.Fatalf("newIntegrationSecret() second error = %v, want nil", err)
	}

	if !strings.HasPrefix(first, integrationSecretPrefix) {
		t.Errorf("newIntegrationSecret() = %q, want prefix %q", first, integrationSecretPrefix)
	}

	if first == second {
		t.Errorf("newIntegrationSecret() returned equal secrets %q", first)
	}

	if hashIntegrationSecret(first) == first {
		t.Error("hashIntegrationSecret(secret) returned the original secret")
	}

	if hashIntegrationSecret(first) != hashIntegrationSecret(first) {
		t.Error("hashIntegrationSecret(secret) is not deterministic")
	}
}
