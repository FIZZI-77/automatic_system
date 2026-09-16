package ticketconsumer

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
	message := kafka.Message{Topic: "ticket.events", Partition: 3, Offset: 42, Key: []byte("ticket-1"), Value: []byte("broken")}
	dlq := dlqMessage("ticket.events", message, errors.New("invalid payload"))
	if dlq.Topic != "ticket.events.dlq" || string(dlq.Key) != "ticket-1" || string(dlq.Value) != "broken" {
		t.Fatalf("unexpected dlq message: %+v", dlq)
	}
	for key, expected := range map[string]string{"x-original-topic": "ticket.events", "x-original-partition": "3", "x-original-offset": "42"} {
		if got := header(dlq, key); got != expected {
			t.Fatalf("header %s: got %q, want %q", key, got, expected)
		}
	}
}
