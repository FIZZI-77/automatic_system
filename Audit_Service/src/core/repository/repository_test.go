package repository

import "testing"

func TestSanitizedRedactsSensitiveValuesRecursively(t *testing.T) {
	source := map[string]any{"password": "plain", "profile": map[string]any{"access_token": "token", "name": "worker"}}
	result := sanitize(source)
	if result["password"] != "[REDACTED]" || result["profile"].(map[string]any)["access_token"] != "[REDACTED]" {
		t.Fatal("sensitive values were not redacted")
	}
	if source["password"] != "plain" || result["profile"].(map[string]any)["name"] != "worker" {
		t.Fatal("sanitization mutated source or removed safe data")
	}
}
