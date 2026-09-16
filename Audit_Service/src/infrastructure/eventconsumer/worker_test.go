package eventconsumer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
)

func TestRetryCurrentRetriesSameMessageUntilSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	attempts := 0
	err := retryCurrent(ctx, func() error {
		attempts++
		if attempts == 1 {
			return errors.New("temporary storage failure")
		}
		return nil
	}, func(int, error) {})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("expected two attempts for the same message, got %d", attempts)
	}
}

func TestDLQMessageKeepsReplayCoordinates(t *testing.T) {
	message := kafka.Message{Topic: "audit.events", Partition: 2, Offset: 17, Key: []byte("event-1"), Value: []byte("broken")}
	dlq := dlqMessage("audit.events", message, errors.New("invalid payload"))
	if dlq.Topic != "audit.events.dlq" || string(dlq.Key) != "event-1" || string(dlq.Value) != "broken" {
		t.Fatalf("unexpected dlq message: %+v", dlq)
	}
	headers := make(map[string]string, len(dlq.Headers))
	for _, item := range dlq.Headers {
		headers[item.Key] = string(item.Value)
	}
	for key, expected := range map[string]string{"x-original-topic": "audit.events", "x-original-partition": "2", "x-original-offset": "17"} {
		if got := headers[key]; got != expected {
			t.Fatalf("header %s: got %q, want %q", key, got, expected)
		}
	}
}
