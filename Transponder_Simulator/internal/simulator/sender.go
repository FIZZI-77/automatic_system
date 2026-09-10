package simulator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type Sender interface {
	Send(context.Context, Event) error
}

type HTTPSender struct {
	url        string
	apiKey     string
	retries    int
	client     *http.Client
	stdout     io.Writer
	retryDelay time.Duration
}

func NewSender(cfg Config) *HTTPSender {
	return &HTTPSender{
		url: cfg.TargetURL, apiKey: cfg.APIKey, retries: cfg.RetryCount,
		client: &http.Client{Timeout: cfg.RequestTimeout},
		stdout: os.Stdout, retryDelay: 250 * time.Millisecond,
	}
}

func (s *HTTPSender) Send(ctx context.Context, event Event) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	if s.url == "" {
		_, err = fmt.Fprintln(s.stdout, string(body))
		return err
	}

	var lastErr error
	for attempt := 0; attempt <= s.retries; attempt++ {
		lastErr = s.sendOnce(ctx, body)
		if lastErr == nil {
			return nil
		}
		if attempt == s.retries {
			break
		}
		timer := time.NewTimer(s.retryDelay * time.Duration(1<<min(attempt, 5)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("send telemetry after %d attempts: %w", s.retries+1, lastErr)
}

func (s *HTTPSender) sendOnce(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "automatic-system-transponder-simulator/1.0")
	if s.apiKey != "" {
		req.Header.Set("X-Transponder-Key", s.apiKey)
	}
	response, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New(response.Status)
	}
	return nil
}
