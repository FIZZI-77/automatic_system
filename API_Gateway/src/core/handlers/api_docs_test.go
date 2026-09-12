package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAPIDocsRequireOptIn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("SWAGGER_ENABLED", "false")
	router := gin.New()
	registerAPIDocs(router)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/swagger/openapi.json", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled docs returned %d", w.Code)
	}
}

func TestAPIDocsEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("SWAGGER_ENABLED", "true")
	router := gin.New()
	registerAPIDocs(router)
	for path, expected := range map[string]string{
		"/swagger/":                     "swagger-ui-bundle.js",
		"/swagger/openapi.json":         `"openapi": "3.0.3"`,
		"/swagger/init.js":              "openapi.json",
		"/swagger/swagger-ui.css":       "swagger-ui",
		"/swagger/swagger-ui-bundle.js": "SwaggerUIBundle",
	} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), expected) {
			t.Errorf("GET %s: status %d, expected content missing", path, w.Code)
		}
	}
}
