package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func TestRedisRateLimiterEnforcesSharedBurst(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	limiter := NewRedisRateLimiter(client, "test")
	router := gin.New()
	router.Use(limiter.Middleware(RateLimitConfig{Name: "global", Limit: 1, Burst: 2, Window: time.Minute}))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	for i, expected := range []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = "192.0.2.1:1234"
		router.ServeHTTP(response, request)
		if response.Code != expected {
			t.Fatalf("request %d: expected %d, got %d", i+1, expected, response.Code)
		}
	}

	if !server.Exists("test:global:192.0.2.1") {
		t.Fatal("rate limit state was not stored in Redis")
	}
}

func TestRedisRateLimiterReturnsUnavailableOnRedisFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 10 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })

	limiter := NewRedisRateLimiter(client, "test")
	router := gin.New()
	router.Use(limiter.Middleware(RateLimitConfig{Name: "global"}))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, response.Code)
	}
}
