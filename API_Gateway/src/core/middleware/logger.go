package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"gateway/pkg/telemetry"
	"gateway/src/core/requestid"

	"github.com/gin-gonic/gin"
)

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		rawQuery := c.Request.URL.RawQuery

		c.Next()
		duration := time.Since(start)
		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		telemetry.ObserveHTTPRequest(
			c.Request.Context(),
			c.Request.Method,
			route,
			c.Writer.Status(),
			duration,
		)

		if rawQuery != "" {
			path += "?" + rawQuery
		}

		requestID, _ := requestid.FromContext(c.Request.Context())
		attributes := []any{
			"request_id", requestID,
			"method", c.Request.Method,
			"path", path,
			"status", c.Writer.Status(),
			"duration_ms", duration.Milliseconds(),
			"client_ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
		}

		if userID := c.GetString("user_id"); userID != "" {
			attributes = append(attributes, "user_id", userID)
		}
		if errors := c.Errors.ByType(gin.ErrorTypePrivate).String(); errors != "" {
			attributes = append(attributes, "errors", errors)
		}

		status := c.Writer.Status()
		switch {
		case status >= http.StatusInternalServerError:
			attributes = append(attributes, "err", errors.New(http.StatusText(status)))
			slog.ErrorContext(c.Request.Context(), "http request failed", attributes...)
		case status >= http.StatusBadRequest:
			slog.WarnContext(c.Request.Context(), "http request rejected", attributes...)
		default:
			slog.InfoContext(c.Request.Context(), "http request completed", attributes...)
		}
	}
}
