package storage

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestUploadSizeEnforcedByS3BeforeConfirmation(t *testing.T) {
	endpoint := os.Getenv("S3_SECURITY_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("set S3_SECURITY_TEST_ENDPOINT for isolated MinIO")
	}
	store := New(Config{Endpoint: endpoint, Region: "us-east-1", AccessKey: "security-test", SecretKey: "security-test-secret", Bucket: "security-test", UsePathStyle: true})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := store.EnsureBucket(ctx); err != nil {
		t.Fatal(err)
	}
	url, err := store.UploadURL(ctx, "upload", "text/csv", "", 4, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Delete(context.Background(), "upload")
	for _, test := range []struct {
		body string
		want int
	}{{"longer-than-declared", http.StatusForbidden}, {"data", http.StatusOK}} {
		request, err := http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader(test.body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "text/csv")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != test.want {
			t.Fatalf("PUT %d bytes status=%d, want %d", len(test.body), response.StatusCode, test.want)
		}
	}
}
