package statistics

import (
	"math"
	"testing"
)

func TestPercentile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		values     []float64
		percentile float64
		want       float64
	}{{"median", []float64{4, 1, 3, 2}, 50, 2.5}, {"p95 interpolation", []float64{0, 100}, 95, 95}}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := Percentile(test.values, test.percentile)
			if err != nil || math.Abs(got-test.want) > 1e-9 {
				t.Errorf("Percentile(%v, %v) = %v, %v, want %v, nil", test.values, test.percentile, got, err, test.want)
			}
		})
	}
}

func TestLinearRegression(t *testing.T) {
	t.Parallel()
	got, err := LinearRegression([]Point{{0, 1}, {1, 3}, {2, 5}})
	if err != nil || got.Slope != 2 || got.Intercept != 1 || got.RSquared != 1 {
		t.Errorf("LinearRegression(linear) = %+v, %v, want slope=2 intercept=1 r2=1", got, err)
	}
}
func TestBacklogSlope(t *testing.T) {
	t.Parallel()
	got, err := BacklogSlope([]Point{{0, 10}, {10, 20}, {20, 30}})
	if err != nil || got != 1 {
		t.Errorf("BacklogSlope(samples) = %v, %v, want 1, nil", got, err)
	}
}
