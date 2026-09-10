package models

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func FuzzCreateCategoryInputValidate(f *testing.F) {
	f.Add("water", "Water", "Water category")
	f.Add("Water", "Water", "Uppercase code")
	f.Add("", "", "")
	f.Add(strings.Repeat("a", 101), "Name", "Description")

	f.Fuzz(func(t *testing.T, code string, name string, description string) {
		in := &CreateCategoryInput{
			Code:        code,
			Name:        name,
			Description: &description,
		}

		_ = in.Validate()
	})
}

func FuzzCreateTicketInputValidate(f *testing.F) {
	f.Add("Title", "Description", "Address", 55.751244, 37.618423)
	f.Add("", "", "", 0.0, 0.0)
	f.Add(strings.Repeat("a", 256), "Description", "Address", 91.0, 181.0)

	f.Fuzz(func(t *testing.T, title string, description string, address string, latitude float64, longitude float64) {
		in := &CreateTicketInput{
			DepartmentID: uuid.New(),
			CategoryID:   uuid.New(),
			UserID:       uuid.New(),
			Title:        title,
			Description:  description,
			Priority:     TicketPriorityMedium,
			Address:      address,
			Latitude:     latitude,
			Longitude:    longitude,
		}

		_ = in.Validate()
	})
}

func FuzzUpdateTicketInputValidate(f *testing.F) {
	f.Add("Updated title", "Updated description", "New address", 55.7, 37.6, true)
	f.Add("", "", "", 91.0, 37.6, true)
	f.Add("Title", "Description", "Address", 55.7, 181.0, true)
	f.Add("Title", "Description", "Address", 55.7, 37.6, false)

	f.Fuzz(func(t *testing.T, title string, description string, address string, latitude float64, longitude float64, includeLongitude bool) {
		in := &UpdateTicketInput{
			TicketID:    uuid.New(),
			Title:       &title,
			Description: &description,
			Address:     &address,
			Latitude:    &latitude,
			UpdatedBy:   uuidPtr(uuid.New()),
		}

		if includeLongitude {
			in.Longitude = &longitude
		}

		_ = in.Validate()
	})
}

func uuidPtr(value uuid.UUID) *uuid.UUID {
	return &value
}
