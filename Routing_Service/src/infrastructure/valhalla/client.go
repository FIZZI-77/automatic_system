package valhalla

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"routing/models"
)

type Config struct {
	BaseURL string
	Timeout time.Duration
}

type Client struct {
	baseURL string
	http    *http.Client
}

func New(config Config) (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	if baseURL == "" {
		return nil, errors.New("valhalla: base URL is required")
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: config.Timeout},
	}, nil
}

type location struct {
	Latitude  float64 `json:"lat"`
	Longitude float64 `json:"lon"`
}

type dateTime struct {
	Type  int    `json:"type"`
	Value string `json:"value"`
}

type routeRequest struct {
	Locations         []location        `json:"locations"`
	Costing           string            `json:"costing"`
	CostingOptions    map[string]any    `json:"costing_options,omitempty"`
	DateTime          *dateTime         `json:"date_time,omitempty"`
	Units             string            `json:"units"`
	DirectionsOptions map[string]string `json:"directions_options"`
	Alternates        int               `json:"alternates,omitempty"`
}

type routeResponse struct {
	Trip struct {
		Summary struct {
			Length float64 `json:"length"`
			Time   float64 `json:"time"`
		} `json:"summary"`
		Shape string `json:"shape"`
		Legs  []struct {
			Summary struct {
				Length float64 `json:"length"`
				Time   float64 `json:"time"`
			} `json:"summary"`
		} `json:"legs"`
		Locations []location `json:"locations"`
	} `json:"trip"`
}

type matrixRequest struct {
	Sources        []location     `json:"sources"`
	Targets        []location     `json:"targets"`
	Costing        string         `json:"costing"`
	CostingOptions map[string]any `json:"costing_options,omitempty"`
	DateTime       *dateTime      `json:"date_time,omitempty"`
	Units          string         `json:"units"`
}

type matrixResponse struct {
	SourcesToTargets [][]struct {
		Distance *float64 `json:"distance"`
		Time     *float64 `json:"time"`
	} `json:"sources_to_targets"`
}

func (c *Client) BuildRoute(
	ctx context.Context,
	in *models.BuildRouteInput,
) (*models.CalculatedRoute, error) {
	points := make([]models.Point, 0, len(in.Waypoints)+2)
	points = append(points, in.Origin)
	points = append(points, in.Waypoints...)
	points = append(points, in.Destination)

	request := routeRequest{
		Locations:         toLocations(points),
		Costing:           costing(in.Options),
		CostingOptions:    costingOptions(in.Options),
		DateTime:          departureTime(in.Options),
		Units:             "kilometers",
		DirectionsOptions: map[string]string{"units": "kilometers"},
	}
	if in.Options.Alternatives {
		request.Alternates = 2
	}

	var response routeResponse
	if err := c.post(ctx, "/route", request, &response); err != nil {
		return nil, err
	}

	legs := make([]models.RouteLeg, 0, len(response.Trip.Legs))
	for index, leg := range response.Trip.Legs {
		if index+1 >= len(points) {
			break
		}
		legs = append(legs, models.RouteLeg{
			From:            points[index],
			To:              points[index+1],
			DistanceMeters:  leg.Summary.Length * 1000,
			DurationSeconds: int64(leg.Summary.Time),
		})
	}

	snapped := make([]models.Point, 0, len(response.Trip.Locations))
	for _, point := range response.Trip.Locations {
		snapped = append(snapped, models.Point{
			Latitude:  point.Latitude,
			Longitude: point.Longitude,
		})
	}

	return &models.CalculatedRoute{
		Summary: models.RouteSummary{
			DistanceMeters:  response.Trip.Summary.Length * 1000,
			DurationSeconds: int64(response.Trip.Summary.Time),
		},
		EncodedPolyline: response.Trip.Shape,
		Legs:            legs,
		SnappedPoints:   snapped,
		Engine:          "valhalla",
	}, nil
}

func (c *Client) BuildMatrix(
	ctx context.Context,
	in *models.BuildMatrixInput,
) ([]models.MatrixCell, error) {
	request := matrixRequest{
		Sources:        toLocations(in.Sources),
		Targets:        toLocations(in.Targets),
		Costing:        costing(in.Options),
		CostingOptions: costingOptions(in.Options),
		DateTime:       departureTime(in.Options),
		Units:          "kilometers",
	}

	var response matrixResponse
	if err := c.post(ctx, "/sources_to_targets", request, &response); err != nil {
		return nil, err
	}

	cells := make([]models.MatrixCell, 0, len(in.Sources)*len(in.Targets))
	for sourceIndex, targets := range response.SourcesToTargets {
		for targetIndex, value := range targets {
			cell := models.MatrixCell{
				SourceIndex: int32(sourceIndex),
				TargetIndex: int32(targetIndex),
			}
			if value.Distance != nil && value.Time != nil {
				cell.DistanceMeters = *value.Distance * 1000
				cell.DurationSeconds = int64(*value.Time)
				cell.Reachable = true
			}
			cells = append(cells, cell)
		}
	}
	return cells, nil
}

func (c *Client) post(ctx context.Context, path string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("valhalla: encode request: %w", err)
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("valhalla: create request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%w: valhalla request: %v", models.ErrDependencyUnavailable, err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		return fmt.Errorf(
			"%w: valhalla status %d: %s",
			models.ErrDependencyUnavailable,
			response.StatusCode,
			strings.TrimSpace(string(data)),
		)
	}
	if err = json.NewDecoder(response.Body).Decode(output); err != nil {
		return fmt.Errorf("%w: valhalla response: %v", models.ErrDependencyUnavailable, err)
	}
	return nil
}

func toLocations(points []models.Point) []location {
	result := make([]location, 0, len(points))
	for _, point := range points {
		result = append(result, location{
			Latitude:  point.Latitude,
			Longitude: point.Longitude,
		})
	}
	return result
}

func costing(options models.RouteOptions) string {
	if options.TravelMode == "" {
		return string(models.TravelModeAuto)
	}
	return string(options.TravelMode)
}

func departureTime(options models.RouteOptions) *dateTime {
	if options.DepartureAt == nil {
		return nil
	}
	return &dateTime{
		Type:  1,
		Value: options.DepartureAt.Format("2006-01-02T15:04"),
	}
}

func costingOptions(options models.RouteOptions) map[string]any {
	if options.TravelMode != models.TravelModeTruck || options.Vehicle == nil {
		return nil
	}
	values := map[string]any{}
	if options.Vehicle.HeightMeters != nil {
		values["height"] = *options.Vehicle.HeightMeters
	}
	if options.Vehicle.WidthMeters != nil {
		values["width"] = *options.Vehicle.WidthMeters
	}
	if options.Vehicle.LengthMeters != nil {
		values["length"] = *options.Vehicle.LengthMeters
	}
	if options.Vehicle.WeightTons != nil {
		values["weight"] = *options.Vehicle.WeightTons
	}
	if options.Vehicle.AxleLoadTons != nil {
		values["axle_load"] = *options.Vehicle.AxleLoadTons
	}
	if options.Vehicle.HazardousMaterials {
		values["hazmat"] = true
	}
	return map[string]any{"truck": values}
}
