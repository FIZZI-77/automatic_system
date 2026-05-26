package middleware

import (
	"log"
	"time"

	"gateway/src/core/requestid"

	"github.com/gin-gonic/gin"
)

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		rawQuery := c.Request.URL.RawQuery

		c.Next()

		if rawQuery != "" {
			path += "?" + rawQuery
		}

		requestID, _ := requestid.FromContext(c.Request.Context())
		log.Printf(
			"request_id=%s method=%s path=%s status=%d latency=%s client_ip=%s errors=%q",
			requestID,
			c.Request.Method,
			path,
			c.Writer.Status(),
			time.Since(start),
			c.ClientIP(),
			c.Errors.ByType(gin.ErrorTypePrivate).String(),
		)
	}
}
