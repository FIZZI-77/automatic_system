package models

import (
	"errors"
	"testing"
)

func TestBuildRouteInputValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   *BuildRouteInput
		wantErr bool
	}{
		{
			name: "valid",
			input: &BuildRouteInput{
				Origin:      Point{Latitude: 55.75, Longitude: 37.61},
				Destination: Point{Latitude: 55.76, Longitude: 37.62},
				Options:     RouteOptions{TravelMode: TravelModeTruck},
			},
		},
		{
			name: "invalid latitude",
			input: &BuildRouteInput{
				Origin:      Point{Latitude: 91, Longitude: 37.61},
				Destination: Point{Latitude: 55.76, Longitude: 37.62},
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.input.Validate()
			if test.wantErr != errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func FuzzPointValidate(f *testing.F) {
	f.Add(55.75, 37.61)
	f.Add(91.0, 181.0)
	f.Fuzz(func(t *testing.T, latitude, longitude float64) {
		err := (Point{
			Latitude:  latitude,
			Longitude: longitude,
		}).Validate("point")
		valid := latitude >= -90 &&
			latitude <= 90 &&
			longitude >= -180 &&
			longitude <= 180
		if valid && err != nil {
			t.Fatalf("valid point rejected: %v", err)
		}
	})
}
