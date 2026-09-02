package statistics

import (
	"errors"
	"math"
	"sort"
)

var ErrInsufficientData = errors.New("insufficient data")

type Point struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}
type Regression struct {
	Slope     float64 `json:"slope"`
	Intercept float64 `json:"intercept"`
	RSquared  float64 `json:"r_squared"`
}

func Percentile(values []float64, percentile float64) (float64, error) {
	if len(values) == 0 || percentile < 0 || percentile > 100 {
		return 0, ErrInsufficientData
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	if len(sorted) == 1 {
		return sorted[0], nil
	}
	position := percentile / 100 * float64(len(sorted)-1)
	lower, upper := int(math.Floor(position)), int(math.Ceil(position))
	if lower == upper {
		return sorted[lower], nil
	}
	weight := position - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight, nil
}

func LinearRegression(points []Point) (Regression, error) {
	if len(points) < 2 {
		return Regression{}, ErrInsufficientData
	}
	var sumX, sumY float64
	for _, point := range points {
		sumX += point.X
		sumY += point.Y
	}
	meanX, meanY := sumX/float64(len(points)), sumY/float64(len(points))
	var numerator, denominator, total float64
	for _, point := range points {
		dx, dy := point.X-meanX, point.Y-meanY
		numerator += dx * dy
		denominator += dx * dx
		total += dy * dy
	}
	if denominator == 0 {
		return Regression{}, ErrInsufficientData
	}
	slope := numerator / denominator
	intercept := meanY - slope*meanX
	residual := 0.0
	for _, point := range points {
		delta := point.Y - (intercept + slope*point.X)
		residual += delta * delta
	}
	rSquared := 1.0
	if total > 0 {
		rSquared = 1 - residual/total
	}
	return Regression{Slope: slope, Intercept: intercept, RSquared: rSquared}, nil
}

func BacklogSlope(samples []Point) (float64, error) {
	regression, err := LinearRegression(samples)
	if err != nil {
		return 0, err
	}
	return regression.Slope, nil
}
