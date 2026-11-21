package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"gateway/models"

	"github.com/gin-gonic/gin"
)

// ListIncidents возвращает историю объекта администраторам и диспетчерам.
func (h *AssetHandler) ListIncidents(c *gin.Context) {
	if !actorHasRole(c, "admin") && !actorHasRole(c, "dispatcher") {
		writeAPIError(c, http.StatusForbidden, "PERMISSION_DENIED", "Недостаточно прав для чтения истории объекта")
		return
	}
	var in models.ListAssetIncidentsRequest
	if !bindJSON(c, &in) {
		return
	}
	limit := 20
	if in.Limit != nil {
		limit = *in.Limit
	}
	url := fmt.Sprintf("%s/internal/assets/%s/incidents?limit=%d&offset=%d", h.historyURL, in.AssetID, limit, in.Offset)
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, url, nil)
	if err != nil {
		writeAPIError(c, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "История объекта недоступна")
		return
	}
	res, err := h.historyHTTP.Do(req)
	if err != nil {
		writeAPIError(c, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "История объекта недоступна")
		return
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		writeAPIError(c, http.StatusNotFound, "NOT_FOUND", "Объект не найден")
		return
	}
	var payload models.ListAssetIncidentsResponse
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&payload) != nil {
		writeAPIError(c, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "История объекта недоступна")
		return
	}
	c.JSON(http.StatusOK, &models.ListAssetIncidentsResponse{
		Incidents: payload.Incidents,
		Total:     payload.Total,
	})
}
