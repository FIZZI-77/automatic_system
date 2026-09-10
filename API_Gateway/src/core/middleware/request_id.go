package middleware

import (
	"strings"

	"gateway/src/core/requestid"

	"github.com/gin-gonic/gin"
)

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := strings.TrimSpace(c.GetHeader(requestid.Header))
		if id == "" {
			id = requestid.New()
		}

		ctx := requestid.WithContext(c.Request.Context(), id)
		c.Request = c.Request.WithContext(ctx)
		c.Set("request_id", id)
		c.Header(requestid.Header, id)

		c.Next()
	}
}
