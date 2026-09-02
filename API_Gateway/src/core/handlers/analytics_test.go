package handlers

import (
	"net/http/httptest"
	"testing"

	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/metadata"
)

func TestAnalyticsContextPropagatesActorRoles(t *testing.T) {
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = httptest.NewRequest("POST", "/analytics/tickets/overview", nil)
	context.Set("roles", []string{"admin", "dispatcher"})

	outgoing, ok := metadata.FromOutgoingContext(analyticsContext(context))
	if !ok {
		t.Fatal("analyticsContext() did not create outgoing metadata")
	}
	if got := outgoing.Get("x-actor-roles"); len(got) != 1 || got[0] != "admin,dispatcher" {
		t.Fatalf("x-actor-roles = %v, want [admin,dispatcher]", got)
	}
}

func TestOperationalLatencyDimension(t *testing.T) {
	tests := map[string]analyticsv1.OperationalLatencyDimension{
		"department":      analyticsv1.OperationalLatencyDimension_OPERATIONAL_LATENCY_DIMENSION_DEPARTMENT,
		"CATEGORY":        analyticsv1.OperationalLatencyDimension_OPERATIONAL_LATENCY_DIMENSION_CATEGORY,
		"assignment_mode": analyticsv1.OperationalLatencyDimension_OPERATIONAL_LATENCY_DIMENSION_ASSIGNMENT_MODE,
		"engine":          analyticsv1.OperationalLatencyDimension_OPERATIONAL_LATENCY_DIMENSION_ENGINE,
		"failure_code":    analyticsv1.OperationalLatencyDimension_OPERATIONAL_LATENCY_DIMENSION_FAILURE_CODE,
	}
	for input, want := range tests {
		if got := operationalLatencyDimension(input); got != want {
			t.Errorf("operationalLatencyDimension(%q) = %v, want %v", input, got, want)
		}
	}
	if got := operationalLatencyDimension("unknown"); got != analyticsv1.OperationalLatencyDimension_OPERATIONAL_LATENCY_DIMENSION_UNSPECIFIED {
		t.Errorf("operationalLatencyDimension(unknown) = %v, want unspecified", got)
	}
}
