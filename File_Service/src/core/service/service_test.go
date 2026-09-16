package service

import (
	"testing"

	"file/models"
)

func TestDownloadableStatus(t *testing.T) {
	tests := []struct {
		status models.Status
		want   bool
	}{
		{models.StatusPendingUpload, false},
		{models.StatusUploaded, true},
		{models.StatusLinked, true},
		{models.StatusQuarantined, false},
		{models.StatusDeleted, false},
	}
	for _, test := range tests {
		if got := downloadable(test.status); got != test.want {
			t.Errorf("downloadable(%q) = %v, want %v", test.status, got, test.want)
		}
	}
}
