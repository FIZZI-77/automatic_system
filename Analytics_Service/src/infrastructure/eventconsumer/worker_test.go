package eventconsumer

import (
	"errors"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
)

func TestEventVersion(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		payload map[string]any
		want    uint32
	}{
		{name: "header wins", headers: map[string]string{"event_version": "3"}, payload: map[string]any{"event_version": float64(2)}, want: 3},
		{name: "snake case payload", payload: map[string]any{"event_version": float64(2)}, want: 2},
		{name: "camel case payload", payload: map[string]any{"EventVersion": float64(4)}, want: 4},
		{name: "legacy defaults to one", payload: map[string]any{}, want: 1},
		{name: "invalid defaults to one", headers: map[string]string{"event_version": "invalid"}, want: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := eventVersion(test.headers, test.payload); got != test.want {
				t.Errorf("eventVersion(%v, %v) = %d, want %d", test.headers, test.payload, got, test.want)
			}
		})
	}
}

func TestDeadLetterMessagePreservesSourceAndDiagnostics(t *testing.T) {
	t.Parallel()
	source := kafka.Message{
		Key: []byte("key"), Value: []byte("payload"), Partition: 3, Offset: 42,
		Headers: []kafka.Header{{Key: "event_type", Value: []byte("dispatch.failed")}},
	}
	message := deadLetterMessage("dispatch.events.v1", source, errors.New("store unavailable"), 5)
	if string(message.Key) != "key" || string(message.Value) != "payload" {
		t.Fatalf("deadLetterMessage() lost source key/value: %+v", message)
	}
	want := map[string]string{
		"event_type": "dispatch.failed", "source_topic": "dispatch.events.v1",
		"source_partition": "3", "source_offset": "42", "processing_attempts": "5",
		"processing_error": "store unavailable",
	}
	for _, header := range message.Headers {
		if _, exists := want[header.Key]; exists {
			if string(header.Value) != want[header.Key] {
				t.Errorf("header %s = %q, want %q", header.Key, header.Value, want[header.Key])
			}
			delete(want, header.Key)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing DLQ headers: %v", want)
	}
}

func TestProcessingRetryDelayIsBounded(t *testing.T) {
	t.Parallel()
	want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond, 1600 * time.Millisecond, 2 * time.Second}
	for index, expected := range want {
		if got := processingRetryDelay(index + 1); got != expected {
			t.Errorf("processingRetryDelay(%d) = %v, want %v", index+1, got, expected)
		}
	}
}
