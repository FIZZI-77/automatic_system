package main

import (
	"strings"
	"testing"
)

func TestReplayIdentifiers(t *testing.T) {
	t.Parallel()
	versions := map[string]bool{"v1": true, "v27": true, "1": false, "v0": false, "v1;DROP TABLE": false}
	for value, want := range versions {
		if got := versionPattern.MatchString(value); got != want {
			t.Errorf("versionPattern.MatchString(%q) = %v, want %v", value, got, want)
		}
	}
	databases := map[string]bool{"analytics": true, "analytics_test2": true, "analytics-test": false, "x;DROP": false}
	for value, want := range databases {
		if got := identifierPattern.MatchString(value); got != want {
			t.Errorf("identifierPattern.MatchString(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestReconcileCounts(t *testing.T) {
	t.Parallel()
	source := counts{Events: 10, Eligible: 8, Unknown: 2}
	if err := reconcileCounts("test", source, source); err != nil {
		t.Fatalf("reconcileCounts(equal) error = %v", err)
	}
	for name, projection := range map[string]counts{
		"missing event":     {Events: 9, Eligible: 8, Unknown: 1},
		"wrong eligibility": {Events: 10, Eligible: 9, Unknown: 1},
		"extra event":       {Events: 11, Eligible: 9, Unknown: 2},
	} {
		t.Run(name, func(t *testing.T) {
			err := reconcileCounts("test", source, projection)
			if err == nil || !strings.Contains(err.Error(), "test reconciliation failed") {
				t.Fatalf("reconcileCounts(%+v, %+v) error = %v", source, projection, err)
			}
		})
	}
}
