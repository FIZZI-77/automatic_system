package parser

import (
	"strings"
	"testing"
)

func TestK6Summary(t *testing.T) {
	t.Parallel()
	input := `{"metrics":{"http_req_duration":{"values":{"avg":10,"med":8,"p(95)":20,"p(99)":30}},"http_req_failed":{"values":{"rate":0.001}}}}`
	got, err := K6Summary(strings.NewReader(input), 100)
	if err != nil || got.Throughput != 100 || got.P95MS != 20 || got.P99MS != 30 || got.ErrorRate != .001 {
		t.Errorf("K6Summary(input, 100) = %+v, %v, want throughput=100 p95=20 p99=30 error=.001", got, err)
	}
}
