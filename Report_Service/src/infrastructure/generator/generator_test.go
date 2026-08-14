package generator

import (
	"report/models"
	"testing"
)

func TestFormats(t *testing.T) {
	for _, f := range []models.Format{models.FormatCSV, models.FormatXLSX, models.FormatPDF} {
		a, e := New().Generate(f, "test", [][]string{{"name", "value"}, {"created", "10"}})
		if e != nil {
			t.Fatalf("%s: %v", f, e)
		}
		if len(a.Data) == 0 || a.ContentType == "" {
			t.Fatalf("empty %s artifact", f)
		}
	}
}
