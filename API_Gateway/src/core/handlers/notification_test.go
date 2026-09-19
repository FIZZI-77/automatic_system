package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
)

func TestNotificationWebSocketReturnsWhenClientDisconnects(t *testing.T) {
	gin.SetMode(gin.TestMode)
	redisServer := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	handler := NewNotificationHandler(nil, redisClient, "notifications:")
	done := make(chan struct{})
	router := gin.New()
	router.GET("/notifications/ws", func(c *gin.Context) {
		c.Set("user_id", "user-1")
		handler.WebSocket(c)
		close(done)
	})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	webSocketURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/notifications/ws"
	conn, response, err := websocket.DefaultDialer.Dial(webSocketURL, http.Header{})
	if err != nil {
		t.Fatalf("dial websocket: %v (response: %v)", err, response)
	}
	if err = conn.Close(); err != nil {
		t.Fatalf("close websocket: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("websocket handler did not return after client disconnect")
	}
}
