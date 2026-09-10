package repository

import (
	"strings"
	"testing"
	"time"
)

func TestSLAListSelect(t *testing.T) {
	query := strings.Replace(slaSelect, " FROM ticket_slas", ",count(*) OVER() FROM ticket_slas", 1)
	if strings.Contains(query, "FROM ticket_slas,count") || !strings.Contains(query, "count(*) OVER() FROM ticket_slas") {
		t.Fatalf("invalid list query: %s", query)
	}
}

func TestWarningReached(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := start.Add(100 * time.Minute)
	if warningReached(start, deadline, 80, start.Add(79*time.Minute)) {
		t.Fatal("warning fired early")
	}
	if !warningReached(start, deadline, 80, start.Add(80*time.Minute)) {
		t.Fatal("warning did not fire")
	}
}
