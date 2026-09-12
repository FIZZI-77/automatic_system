package handlers

import (
	_ "embed"
	"io/fs"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files/v2"
)

//go:embed openapi.json
var openAPISpec []byte

const swaggerPage = `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Automatic City Services API</title>
  <link rel="stylesheet" href="./swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="./swagger-ui-bundle.js"></script>
  <script src="./init.js"></script>
</body>
</html>`

const swaggerInit = `SwaggerUIBundle({ url: './openapi.json', dom_id: '#swagger-ui', deepLinking: true,
  presets: [SwaggerUIBundle.presets.apis] });`

func registerAPIDocs(router *gin.Engine) {
	if os.Getenv("SWAGGER_ENABLED") != "true" {
		return
	}
	router.GET("/swagger/", func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:")
		c.Header("Referrer-Policy", "no-referrer")
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(swaggerPage))
	})
	router.GET("/swagger/openapi.json", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/json", openAPISpec)
	})
	router.GET("/swagger/init.js", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/javascript", []byte(swaggerInit))
	})
	for _, asset := range []struct {
		name        string
		contentType string
	}{
		{"swagger-ui.css", "text/css"},
		{"swagger-ui-bundle.js", "application/javascript"},
	} {
		router.GET("/swagger/"+asset.name, func(c *gin.Context) {
			content, err := fs.ReadFile(swaggerFiles.FS, asset.name)
			if err != nil {
				c.Status(http.StatusInternalServerError)
				return
			}
			c.Data(http.StatusOK, asset.contentType, content)
		})
	}
}
