package simulator

import (
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"testing"
	"time"
)

type recordingSender struct {
	mu     sync.Mutex
	events []Event
	err    error
}

func (s *recordingSender) Send(_ context.Context, event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return s.err
}

func TestRunnerSendsRouteOnceInOrder(t *testing.T) {
	sender := &recordingSender{}
	runner := NewRunner(
		Config{VehicleID: "v", BrigadeID: "b", DeviceID: "d", Interval: time.Millisecond},
		Route{Points: []Point{{Latitude: 1}, {Latitude: 2}, {Latitude: 3}}},
		sender, log.New(io.Discard, "", 0),
	)
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(sender.events) != 3 {
		t.Fatalf("events = %d, want 3", len(sender.events))
	}
	for index, event := range sender.events {
		if event.Payload.Sequence != uint64(index+1) || event.Payload.Latitude != float64(index+1) {
			t.Fatalf("event %d = %+v", index, event.Payload)
		}
	}
}

func TestRunnerStopsOnSenderError(t *testing.T) {
	senderErr := errors.New("send failed")
	runner := NewRunner(
		Config{Interval: time.Millisecond},
		Route{Points: []Point{{}}},
		&recordingSender{err: senderErr}, log.New(io.Discard, "", 0),
	)
	err := runner.Run(context.Background())
	if err == nil || !errors.Is(err, senderErr) {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRunnerStopsCleanlyOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := NewRunner(
		Config{LoopRoute: true, Interval: time.Hour},
		Route{Points: []Point{{}}},
		&recordingSender{}, log.New(io.Discard, "", 0),
	)
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}
