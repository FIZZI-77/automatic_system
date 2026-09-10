package simulator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPSenderStdoutMode(t *testing.T) {
	var output bytes.Buffer
	sender := &HTTPSender{stdout: &output}
	event := Event{EventType: "VehiclePositionUpdated"}
	if err := sender.Send(context.Background(), event); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	var decoded Event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &decoded); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	if decoded.EventType != event.EventType {
		t.Fatalf("event type = %q", decoded.EventType)
	}
}

func TestHTTPSenderHeadersAndRetry(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s", request.Method)
		}
		if request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type = %q", request.Header.Get("Content-Type"))
		}
		if request.Header.Get("X-Transponder-Key") != "secret" {
			t.Errorf("transponder key = %q", request.Header.Get("X-Transponder-Key"))
		}
		if attempts.Add(1) < 3 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sender := &HTTPSender{
		url: server.URL, apiKey: "secret", retries: 2,
		client: server.Client(), stdout: &bytes.Buffer{}, retryDelay: time.Millisecond,
	}
	if err := sender.Send(context.Background(), Event{EventType: "VehiclePositionUpdated"}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("attempts = %d, want 3", attempts.Load())
	}
}

func TestHTTPSenderReturnsLastHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()
	sender := &HTTPSender{
		url: server.URL, retries: 0, client: server.Client(),
		stdout: &bytes.Buffer{}, retryDelay: time.Millisecond,
	}
	err := sender.Send(context.Background(), Event{})
	if err == nil || !strings.Contains(err.Error(), "400 Bad Request") {
		t.Fatalf("error = %v", err)
	}
}

func TestHTTPSenderHonorsCanceledContextDuringRetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "temporary", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	sender := &HTTPSender{
		url: server.URL, retries: 3, client: server.Client(),
		stdout: &bytes.Buffer{}, retryDelay: time.Hour,
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	if err := sender.Send(ctx, Event{}); err != context.Canceled {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
