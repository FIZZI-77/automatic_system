package completionconsumer

import (
	"testing"

	"github.com/segmentio/kafka-go"
)

func TestHeaderIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	headers := []kafka.Header{{Key: "Event_Type", Value: []byte(requestedEvent)}}
	if got := header(headers, "event_type"); got != requestedEvent {
		t.Errorf("header(%q) = %q, want %q", "event_type", got, requestedEvent)
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		value  string
		limit  int
		wanted string
	}{
		{name: "short value", value: "error", limit: 10, wanted: "error"},
		{name: "long value", value: "long error", limit: 4, wanted: "long"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := truncate(test.value, test.limit); got != test.wanted {
				t.Errorf("truncate(%q, %d) = %q, want %q", test.value, test.limit, got, test.wanted)
			}
		})
	}
}
