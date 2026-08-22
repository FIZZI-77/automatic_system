package models

import "testing"

func TestFilterDefaultsAreZero(t *testing.T) {
	var f Filter
	if f.Limit != 0 || f.Offset != 0 {
		t.Fatal("unexpected filter defaults")
	}
}
