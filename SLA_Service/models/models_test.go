package models

import (
	"errors"
	"testing"
	"time"
)

func TestRuleValidate(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		want bool
	}{{"valid", Rule{Name: "default", ResponseTime: time.Minute, ResolutionTime: time.Hour, WarningPercent: 80}, false}, {"empty name", Rule{ResponseTime: time.Minute, ResolutionTime: time.Hour, WarningPercent: 80}, true}, {"response after resolution", Rule{Name: "x", ResponseTime: time.Hour, ResolutionTime: time.Minute, WarningPercent: 80}, true}, {"warning range", Rule{Name: "x", ResponseTime: time.Minute, ResolutionTime: time.Hour, WarningPercent: 100}, true}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := c.rule.Validate()
			if errors.Is(e, ErrInvalidArgument) != c.want {
				t.Fatalf("Validate()=%v", e)
			}
		})
	}
}
