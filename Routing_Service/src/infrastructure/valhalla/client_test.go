package valhalla

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"routing/models"
)

func TestClientBuildRouteUsesTruckConstraints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/route" {
				t.Fatalf("path = %s", request.URL.Path)
			}
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if body["costing"] != "truck" {
				t.Fatalf("costing = %v", body["costing"])
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(
				`{"trip":{"summary":{"length":1.5,"time":120},` +
					`"shape":"shape","legs":[{"summary":{"length":1.5,"time":120}}],` +
					`"locations":[{"lat":55.75,"lon":37.61},{"lat":55.76,"lon":37.62}]}}`,
			))
		},
	))
	defer server.Close()

	client, err := New(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	height := 3.2
	route, err := client.BuildRoute(
		context.Background(),
		&models.BuildRouteInput{
			Origin:      models.Point{Latitude: 55.75, Longitude: 37.61},
			Destination: models.Point{Latitude: 55.76, Longitude: 37.62},
			Options: models.RouteOptions{
				TravelMode: models.TravelModeTruck,
				Vehicle: &models.VehicleConstraints{
					HeightMeters: &height,
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("build route: %v", err)
	}
	if route.Summary.DistanceMeters != 1500 ||
		route.Summary.DurationSeconds != 120 {
		t.Fatalf("route = %#v", route)
	}
}

func TestMergePolyline6JoinsValhallaLegShapes(t *testing.T) {
	first := []polylinePoint{{55755800, 37617300}, {55756000, 37618000}}
	second := []polylinePoint{{55756000, 37618000}, {55757000, 37620000}}
	merged := decodePolyline6(mergePolyline6([]string{encodePolyline6(first), encodePolyline6(second)}))
	if len(merged) != 3 || merged[0] != first[0] || merged[1] != first[1] || merged[2] != second[1] {
		t.Fatalf("merged points = %#v", merged)
	}
}
