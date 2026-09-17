package middleware

import (
	"net/url"
	"strings"
	"testing"
)

func TestSafeRequestPathRedactsSecrets(t *testing.T) {
	t.Parallel()

	requestURL, err := url.Parse("/notifications/ws?access_token=secret.jwt&filter=open&API_KEY=private")
	if err != nil {
		t.Fatal(err)
	}

	got := safeRequestPath(requestURL)
	if strings.Contains(got, "secret.jwt") || strings.Contains(got, "private") {
		t.Fatalf("safe path leaked a secret: %s", got)
	}
	if !strings.Contains(got, "filter=open") || strings.Count(got, "%5BREDACTED%5D") != 2 {
		t.Fatalf("safe path does not preserve public parameters and redact secrets: %s", got)
	}
}
