package middleware

import (
	"log"
	"strconv"
	"strings"
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
		fields := []string{
			"request_id=" + requestID,
			"method=" + c.Request.Method,
			"path=" + path,
			"status=" + strconv.Itoa(c.Writer.Status()),
			"duration=" + strconv.FormatInt(time.Since(start).Milliseconds(), 10),
			"client_ip=" + c.ClientIP(),
			"user_agent=" + strconv.Quote(c.Request.UserAgent()),
		}

		if userID := c.GetString("user_id"); userID != "" {
			fields = append(fields, "user_id="+userID)
		}
		if errors := c.Errors.ByType(gin.ErrorTypePrivate).String(); errors != "" {
			fields = append(fields, "errors="+strconv.Quote(errors))
		}

		log.Printf("http request completed %s", strings.Join(fields, " "))
	}
}
