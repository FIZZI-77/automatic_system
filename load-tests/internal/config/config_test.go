package config

import "testing"

func TestValidateDestructive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		environment Environment
		allowed     bool
		wantErr     bool
	}{{"test allowed", Environment{Name: "local-test", Namespace: "automatic-system-load"}, true, false}, {"flag required", Environment{Name: "local-test", Namespace: "automatic-system-load"}, false, true}, {"production forbidden", Environment{Name: "production", Namespace: "automatic-system"}, true, true}}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateDestructive(test.environment, test.allowed)
			if (err != nil) != test.wantErr {
				t.Errorf("ValidateDestructive(%+v, %v) error = %v, wantErr %v", test.environment, test.allowed, err, test.wantErr)
			}
		})
	}
}
