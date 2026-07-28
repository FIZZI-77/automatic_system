package simulator

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type Point struct {
	Latitude  float64  `json:"latitude"`
	Longitude float64  `json:"longitude"`
	SpeedKMH  *float64 `json:"speed_kmh,omitempty"`
	Accuracy  *float64 `json:"accuracy_meters,omitempty"`
}

type Route struct {
	Name   string  `json:"name"`
	Points []Point `json:"points"`
}

func LoadRoute(path string) (Route, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Route{}, fmt.Errorf("read %s: %w", path, err)
	}
	var route Route
	if err = json.Unmarshal(data, &route); err != nil {
		return Route{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if err = route.Validate(); err != nil {
		return Route{}, fmt.Errorf("validate %s: %w", path, err)
	}
	return route, nil
}

func (r Route) Validate() error {
	if len(r.Points) == 0 {
		return errors.New("route must contain at least one point")
	}
	for index, point := range r.Points {
		if point.Latitude < -90 || point.Latitude > 90 {
			return fmt.Errorf("point %d latitude must be between -90 and 90", index)
		}
		if point.Longitude < -180 || point.Longitude > 180 {
			return fmt.Errorf("point %d longitude must be between -180 and 180", index)
		}
		if point.SpeedKMH != nil && *point.SpeedKMH < 0 {
			return fmt.Errorf("point %d speed cannot be negative", index)
		}
		if point.Accuracy != nil && *point.Accuracy < 0 {
			return fmt.Errorf("point %d accuracy cannot be negative", index)
		}
	}
	return nil
}
