package service

import "testing"

func TestIsUserFacingEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		eventType string
		want      bool
	}{
		{name: "ticket created", eventType: "ticket.created", want: true},
		{name: "ticket assigned", eventType: "ticket.assigned", want: true},
		{name: "completion report ready", eventType: "ticket.completion_report.generated.v1", want: true},
		{name: "internal SLA event", eventType: "sla.CREATED", want: false},
		{name: "saga command", eventType: "ticket.completion_report.requested.v1", want: false},
		{name: "unknown event", eventType: "audit.recorded", want: false},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := isUserFacingEvent(test.eventType)
			if got != test.want {
				t.Errorf("isUserFacingEvent(%q) = %t, want %t", test.eventType, got, test.want)
			}
		})
	}
}
