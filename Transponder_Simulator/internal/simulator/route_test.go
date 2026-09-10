package simulator

import (
	"strings"
	"testing"
)

func TestRouteValidate(t *testing.T) {
	negative := -1.0
	tests := []struct {
		name    string
		route   Route
		wantErr string
	}{
		{"empty", Route{}, "at least one point"},
		{"valid boundaries", Route{Points: []Point{{Latitude: -90, Longitude: -180}, {Latitude: 90, Longitude: 180}}}, ""},
		{"bad latitude", Route{Points: []Point{{Latitude: 90.01, Longitude: 0}}}, "latitude"},
		{"bad longitude", Route{Points: []Point{{Latitude: 0, Longitude: -180.01}}}, "longitude"},
		{"negative speed", Route{Points: []Point{{SpeedKMH: &negative}}}, "speed"},
		{"negative accuracy", Route{Points: []Point{{Accuracy: &negative}}}, "accuracy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.route.Validate()
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
