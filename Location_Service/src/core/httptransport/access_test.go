package httptransport

import (
	"context"
	"location/models"
	"location/src/core/service"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type positionRecorderStub struct {
	service.PositionService
	calls int
}

func (s *positionRecorderStub) RecordPosition(_ context.Context, input *models.RecordPositionInput) (*models.RecordPositionResult, error) {
	s.calls++
	return &models.RecordPositionResult{Position: &models.Position{EventID: input.EventID}}, nil
}

func TestValidPositionKeyPreservesIngestion(t *testing.T) {
	recorder := &positionRecorderStub{}
	handler := New(&service.Service{PositionService: recorder}, "secret").Routes()
	request := httptest.NewRequest(http.MethodPost, "/v1/positions", strings.NewReader(`{"event_id":"00000000-0000-0000-0000-000000000001","event_type":"VehiclePositionUpdated","payload":{"vehicle_id":"00000000-0000-0000-0000-000000000002","brigade_id":"00000000-0000-0000-0000-000000000003"}}`))
	request.Header.Set("X-Transponder-Key", "secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || recorder.calls != 1 {
		t.Fatalf("valid key status=%d records=%d", response.Code, recorder.calls)
	}
}

func TestPositionAuthenticationFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name, configured, supplied string
		want                       int
	}{
		{"empty config", "", "", http.StatusUnauthorized},
		{"blank config", "  ", "  ", http.StatusUnauthorized},
		{"missing key", "secret", "", http.StatusUnauthorized},
		{"wrong key", "secret", "wrong", http.StatusUnauthorized},
		{"correct key reaches validation", "secret", "secret", http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := New(nil, test.configured).Routes()
			request := httptest.NewRequest(http.MethodPost, "/v1/positions", strings.NewReader(`{}`))
			request.Header.Set("X-Transponder-Key", test.supplied)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d, want %d", response.Code, test.want)
			}
		})
	}
	response := httptest.NewRecorder()
	New(nil, "").Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("health status=%d", response.Code)
	}
}
