package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"asset/src/core/repository"

	"github.com/google/uuid"
)

type incidentEntry struct {
	ID          uuid.UUID  `json:"id"`
	TicketID    *uuid.UUID `json:"ticket_id,omitempty"`
	FailureType string     `json:"failure_type"`
	Description string     `json:"description"`
	Source      string     `json:"source"`
	Priority    string     `json:"priority"`
	Repeated    bool       `json:"repeated"`
	OccurredAt  time.Time  `json:"occurred_at"`
}

// AssetHistoryRoutes обслуживает внутренний маршрут чтения истории для Gateway.
func AssetHistoryRoutes(repo *repository.AssetRepoStruct) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/assets/{id}/incidents", func(w http.ResponseWriter, r *http.Request) {
		id, idErr := uuid.Parse(r.PathValue("id"))
		limit, limitErr := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, offsetErr := strconv.Atoi(r.URL.Query().Get("offset"))
		if idErr != nil || limitErr != nil || offsetErr != nil || limit < 1 || limit > 100 || offset < 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		items, total, err := repo.ListIncidents(r.Context(), id, limit, offset)
		if repository.IsNotFound(err) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		incidents := make([]incidentEntry, 0, len(items))
		for _, item := range items {
			incidents = append(incidents, incidentEntry{
				ID: item.ID, TicketID: item.TicketID, FailureType: item.FailureType,
				Description: item.Description, Source: item.Source, Priority: item.Priority,
				Repeated: item.Repeated, OccurredAt: item.OccurredAt,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Incidents []incidentEntry `json:"incidents"`
			Total     int             `json:"total"`
		}{Incidents: incidents, Total: total})
	})
	return mux
}
