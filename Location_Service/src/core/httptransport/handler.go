package httptransport

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"location/models"
	"location/src/core/service"

	"github.com/google/uuid"
)

type Handler struct {
	service *service.Service
	apiKey  string
}

func New(service *service.Service, apiKey string) *Handler {
	return &Handler{service: service, apiKey: apiKey}
}
func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/positions", h.recordPosition)
	return mux
}

type envelope struct {
	EventID      string    `json:"event_id"`
	EventType    string    `json:"event_type"`
	EventVersion int32     `json:"event_version"`
	OccurredAt   time.Time `json:"occurred_at"`
	Payload      struct {
		DeviceID       string   `json:"device_id"`
		VehicleID      string   `json:"vehicle_id"`
		BrigadeID      string   `json:"brigade_id"`
		Sequence       uint64   `json:"sequence"`
		Latitude       float64  `json:"latitude"`
		Longitude      float64  `json:"longitude"`
		SpeedKMH       float64  `json:"speed_kmh"`
		Heading        float64  `json:"heading"`
		AccuracyMeters float64  `json:"accuracy_meters"`
		AltitudeMeters *float64 `json:"altitude_meters"`
		Simulated      bool     `json:"simulated"`
	} `json:"payload"`
}

func (h *Handler) recordPosition(w http.ResponseWriter, r *http.Request) {
	if h.apiKey != "" && r.Header.Get("X-Transponder-Key") != h.apiKey {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req envelope
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.EventType != "VehiclePositionUpdated" {
		http.Error(w, "unsupported event_type", http.StatusBadRequest)
		return
	}
	eventID, err := uuid.Parse(req.EventID)
	if err != nil {
		http.Error(w, "invalid event_id", http.StatusBadRequest)
		return
	}
	vehicleID, err := uuid.Parse(req.Payload.VehicleID)
	if err != nil {
		http.Error(w, "invalid vehicle_id", http.StatusBadRequest)
		return
	}
	brigadeID, err := uuid.Parse(req.Payload.BrigadeID)
	if err != nil {
		http.Error(w, "invalid brigade_id", http.StatusBadRequest)
		return
	}
	result, err := h.service.RecordPosition(
		r.Context(),
		&models.RecordPositionInput{
			EventID:        eventID,
			EventVersion:   req.EventVersion,
			OccurredAt:     req.OccurredAt,
			DeviceID:       req.Payload.DeviceID,
			VehicleID:      vehicleID,
			BrigadeID:      brigadeID,
			Sequence:       req.Payload.Sequence,
			Latitude:       req.Payload.Latitude,
			Longitude:      req.Payload.Longitude,
			SpeedKMH:       req.Payload.SpeedKMH,
			Heading:        req.Payload.Heading,
			AccuracyMeters: req.Payload.AccuracyMeters,
			AltitudeMeters: req.Payload.AltitudeMeters,
			Simulated:      req.Payload.Simulated,
		},
	)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, models.ErrValidation) || errors.Is(err, models.ErrOutOfOrderPosition) {
			code = http.StatusBadRequest
		}
		http.Error(w, err.Error(), code)
		return
	}
	writeJSON(
		w,
		http.StatusAccepted,
		map[string]any{
			"accepted":  true,
			"duplicate": result.Duplicate,
			"event_id":  result.Position.EventID,
		},
	)
}
func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
