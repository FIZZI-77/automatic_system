package middleware

import (
	"strings"

	"gateway/src/core/idempotency"

	"github.com/gin-gonic/gin"
)

func IdempotencyKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := strings.TrimSpace(c.GetHeader(idempotency.Header))
		if key != "" {
			ctx := idempotency.WithContext(c.Request.Context(), key)
			c.Request = c.Request.WithContext(ctx)
			c.Set("idempotency_key", key)
		}

		c.Next()
	}
}
