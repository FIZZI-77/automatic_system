package capacity

import "testing"

func TestExtrapolationConfidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		evidence ExtrapolationEvidence
		want     string
	}{{"high", ExtrapolationEvidence{3, .9, true, .3, 2}, "HIGH"}, {"medium", ExtrapolationEvidence{2, .75, false, .1, 3}, "MEDIUM"}, {"low", ExtrapolationEvidence{1, .9, true, .5, 8}, "LOW"}}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := ExtrapolationConfidence(test.evidence); got != test.want {
				t.Errorf("ExtrapolationConfidence(%+v) = %q, want %q", test.evidence, got, test.want)
			}
		})
	}
}
