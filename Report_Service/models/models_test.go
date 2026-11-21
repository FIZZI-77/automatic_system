package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCreateInputValidate(t *testing.T) {
	t.Parallel()
	valid := CreateInput{RequestedBy: uuid.New(), Name: "Report", Type: TypeTicketOverview, Format: FormatCSV}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	for _, tt := range []struct {
		name   string
		change func(*CreateInput)
		valid  bool
	}{
		{"valid", func(*CreateInput) {}, true},
		{"missing requester", func(v *CreateInput) { v.RequestedBy = uuid.Nil }, false},
		{"short name", func(v *CreateInput) { v.Name = "ab" }, false},
		{"long name", func(v *CreateInput) { v.Name = string(make([]byte, 161)) }, false},
		{"unknown type", func(v *CreateInput) { v.Type = "UNKNOWN" }, false},
		{"unknown format", func(v *CreateInput) { v.Format = "UNKNOWN" }, false},
		{"reversed dates", func(v *CreateInput) { v.Filter = Filter{From: &end, To: &start} }, false},
		{"equal dates", func(v *CreateInput) { v.Filter = Filter{From: &start, To: &start} }, true},
		{"ordered dates", func(v *CreateInput) { v.Filter = Filter{From: &start, To: &end} }, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := valid
			tt.change(&v)
			if err := v.Validate(); (err == nil) != tt.valid {
				t.Fatalf("Validate(%+v) = %v; want valid=%v", v, err, tt.valid)
			}
		})
	}
	for _, kind := range []Type{TypeTicketOverview, TypeSLASummary, TypeTicketBreakdown, TypeDailyTickets} {
		for _, format := range []Format{FormatPDF, FormatXLSX, FormatCSV} {
			v := valid
			v.Type = kind
			v.Format = format
			if err := v.Validate(); err != nil {
				t.Errorf("Validate(type=%s format=%s) = %v", kind, format, err)
			}
		}
	}
}
