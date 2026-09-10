package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClientRejectsRelativeURL(t *testing.T) {
	t.Parallel()
	if _, err := NewClient("localhost:9090", time.Second); err == nil {
		t.Fatal("NewClient() error = nil, want validation error")
	}
}

func TestSnapshotSeparatesUnavailableQueries(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	snapshot, err := client.Snapshot(context.Background(), []Query{{Name: "cpu", PromQL: "up", ConfirmedBy: "manifest"}, {Name: "queue", PromQL: "unknown"}}, now.Add(-time.Minute), now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snapshot.Results["cpu"]; !ok {
		t.Error("confirmed query result missing")
	}
	if _, ok := snapshot.Unavailable["queue"]; !ok {
		t.Error("unconfirmed query must be unavailable")
	}
}
