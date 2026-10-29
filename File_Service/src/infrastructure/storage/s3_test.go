package storage

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestUploadURLSignsDeclaredLength(t *testing.T) {
	store := New(Config{Endpoint: "http://127.0.0.1:9000", Region: "us-east-1", AccessKey: "test", SecretKey: "test-secret", Bucket: "files", UsePathStyle: true})
	first, err := store.UploadURL(context.Background(), "owner/file", "image/png", "", 12, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(first)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(";"+parsed.Query().Get("X-Amz-SignedHeaders")+";", ";content-length;") {
		t.Fatalf("upload signature does not bind content-length: %s", parsed.Query().Get("X-Amz-SignedHeaders"))
	}
	second, err := store.UploadURL(context.Background(), "owner/file", "image/png", "", 13, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := url.Parse(second)
	if parsed.Query().Get("X-Amz-Signature") == other.Query().Get("X-Amz-Signature") {
		t.Fatal("different upload sizes produced the same signature")
	}
}
