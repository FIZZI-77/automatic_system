package models

import "testing"

func TestOverviewZeroValue(t *testing.T) {
	var v Overview
	if v.Created != 0 || v.CompletionRate != 0 {
		t.Fatal("unexpected zero value")
	}
}
