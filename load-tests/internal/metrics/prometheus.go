package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"
)

type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
}
type Query struct {
	Name        string `json:"name" yaml:"name"`
	PromQL      string `json:"promql" yaml:"promql"`
	ConfirmedBy string `json:"confirmed_by" yaml:"confirmed_by"`
}
type Snapshot struct {
	Start       time.Time                  `json:"start"`
	End         time.Time                  `json:"end"`
	Step        string                     `json:"step"`
	Results     map[string]json.RawMessage `json:"results"`
	Unavailable map[string]string          `json:"unavailable"`
}

func NewClient(rawURL string, timeout time.Duration) (*Client, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse Prometheus URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("parse Prometheus URL: absolute HTTP URL is required")
	}
	return &Client{baseURL: parsed, httpClient: &http.Client{Timeout: timeout}}, nil
}

func (c *Client) Snapshot(ctx context.Context, queries []Query, start, end time.Time, step time.Duration) (Snapshot, error) {
	snapshot := Snapshot{Start: start, End: end, Step: step.String(), Results: make(map[string]json.RawMessage), Unavailable: make(map[string]string)}
	for _, query := range queries {
		if query.ConfirmedBy == "" {
			snapshot.Unavailable[query.Name] = "metric is not confirmed by code or manifests"
			continue
		}
		result, err := c.queryRange(ctx, query.PromQL, start, end, step)
		if err != nil {
			snapshot.Unavailable[query.Name] = err.Error()
			continue
		}
		snapshot.Results[query.Name] = result
	}
	return snapshot, nil
}

func (c *Client) queryRange(ctx context.Context, promQL string, start, end time.Time, step time.Duration) (json.RawMessage, error) {
	endpoint := *c.baseURL
	endpoint.Path = path.Join(endpoint.Path, "/api/v1/query_range")
	values := endpoint.Query()
	values.Set("query", promQL)
	values.Set("start", start.UTC().Format(time.RFC3339Nano))
	values.Set("end", end.UTC().Format(time.RFC3339Nano))
	values.Set("step", step.String())
	endpoint.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create Prometheus request: %w", err)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query Prometheus: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query Prometheus: status %s", response.Status)
	}
	var envelope struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
		Error  string          `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode Prometheus response: %w", err)
	}
	if envelope.Status != "success" {
		return nil, fmt.Errorf("query Prometheus: %s", envelope.Error)
	}
	return envelope.Data, nil
}
