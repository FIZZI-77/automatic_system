package models

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func FuzzCreateDepartmentInputValidate(f *testing.F) {
	f.Add("Roads", "Road maintenance")
	f.Add("", "")
	f.Add("   ", "   ")
	f.Add(strings.Repeat("a", 256), "Description")
	f.Add("Water", strings.Repeat("a", 1001))
	f.Add("Дороги", "Обслуживание дорог")

	f.Fuzz(func(t *testing.T, name string, description string) {
		in := &CreateDepartmentInput{
			Name:        name,
			Description: description,
		}

		err := in.Validate()

		if strings.TrimSpace(name) == "" && err == nil {
			t.Fatal("empty name should be invalid")
		}
	})
}

func FuzzGetDepartmentByIDInputValidate(f *testing.F) {
	validID := uuid.New().String()

	f.Add(validID)
	f.Add("")
	f.Add("bad-id")
	f.Add(uuid.Nil.String())

	f.Fuzz(func(t *testing.T, idRaw string) {
		id, _ := uuid.Parse(idRaw)

		in := &GetDepartmentByIDInput{ID: id}
		err := in.Validate()

		if id == uuid.Nil && err == nil {
			t.Fatal("empty id should be invalid")
		}
	})
}

func FuzzListDepartmentsInputValidate(f *testing.F) {
	f.Add("ACTIVE", "created_at", "desc", int32(20), int32(0), false)
	f.Add("", "", "", int32(0), int32(-10), false)
	f.Add("BAD", "bad", "bad", int32(500), int32(-100), false)
	f.Add("ARCHIVED", "name", "asc", int32(10), int32(5), true)

	f.Fuzz(func(t *testing.T, statusRaw string, sortByRaw string, sortOrderRaw string, limit int32, offset int32, invalidRange bool) {
		var status *DepartmentStatus
		if statusRaw != "" {
			value := DepartmentStatus(statusRaw)
			status = &value
		}

		var createdFrom *time.Time
		var createdTo *time.Time
		if invalidRange {
			from := time.Now()
			to := from.Add(-time.Hour)
			createdFrom = &from
			createdTo = &to
		}

		in := &ListDepartmentsInput{
			Status:      status,
			CreatedFrom: createdFrom,
			CreatedTo:   createdTo,
			SortBy:      DepartmentSortBy(sortByRaw),
			SortOrder:   SortOrder(sortOrderRaw),
			Limit:       limit,
			Offset:      offset,
		}

		_ = in.Validate()
	})
}

func FuzzUpdateDepartmentInputValidate(f *testing.F) {
	validID := uuid.New().String()

	f.Add(validID, "Water", "Water service", "ACTIVE", true, true, true)
	f.Add("", "", "", "", false, false, false)
	f.Add("bad-id", strings.Repeat("a", 256), strings.Repeat("a", 1001), "BAD", true, true, true)
	f.Add(uuid.Nil.String(), "Roads", "", "ARCHIVED", true, false, true)

	f.Fuzz(func(t *testing.T, idRaw string, name string, description string, statusRaw string, includeName bool, includeDescription bool, includeStatus bool) {
		id, _ := uuid.Parse(idRaw)

		var namePtr *string
		if includeName {
			namePtr = &name
		}

		var descriptionPtr *string
		if includeDescription {
			descriptionPtr = &description
		}

		var statusPtr *DepartmentStatus
		if includeStatus {
			value := DepartmentStatus(statusRaw)
			statusPtr = &value
		}

		in := &UpdateDepartmentInput{
			ID:          id,
			Name:        namePtr,
			Description: descriptionPtr,
			Status:      statusPtr,
		}

		err := in.Validate()

		if id == uuid.Nil && err == nil {
			t.Fatal("empty id should be invalid")
		}
		if namePtr == nil && descriptionPtr == nil && statusPtr == nil && err == nil {
			t.Fatal("update without fields should be invalid")
		}
	})
}

func FuzzDeleteDepartmentInputValidate(f *testing.F) {
	validID := uuid.New().String()

	f.Add(validID)
	f.Add("")
	f.Add("bad-id")
	f.Add(uuid.Nil.String())

	f.Fuzz(func(t *testing.T, idRaw string) {
		id, _ := uuid.Parse(idRaw)

		in := &DeleteDepartmentInput{ID: id}
		err := in.Validate()

		if id == uuid.Nil && err == nil {
			t.Fatal("empty id should be invalid")
		}
	})
}
