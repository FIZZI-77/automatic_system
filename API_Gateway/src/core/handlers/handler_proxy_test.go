package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestConfigureTrustedProxiesRejectsSpoofedForwardedAddress(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("TRUSTED_PROXIES", "127.0.0.0/8")

	router := gin.New()
	configureTrustedProxies(router)
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "127.0.0.6:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.200, 198.51.100.25")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Body.String() != "198.51.100.25" {
		t.Fatalf("client IP = %q, want rightmost untrusted proxy address", response.Body.String())
	}
}

func TestConfigureTrustedProxiesIgnoresHeadersFromUntrustedPeer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("TRUSTED_PROXIES", "127.0.0.0/8")

	router := gin.New()
	configureTrustedProxies(router)
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "192.0.2.44:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.200")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Body.String() != "192.0.2.44" {
		t.Fatalf("client IP = %q, want direct peer address", response.Body.String())
	}
}
