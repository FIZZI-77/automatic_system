package models

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func FuzzCreateBrigadeInputValidate(f *testing.F) {
	departmentID := uuid.New().String()

	f.Add(departmentID, "North crew", "Road maintenance", "roads", true)
	f.Add("", "", "", "", false)
	f.Add("bad-id", strings.Repeat("a", 256), strings.Repeat("a", 1001), strings.Repeat("a", 256), true)
	f.Add(uuid.Nil.String(), "Бригада", "Описание", "специализация", true)

	f.Fuzz(func(t *testing.T, departmentIDRaw string, name string, description string, specialization string, includeSpecialization bool) {
		departmentID, _ := uuid.Parse(departmentIDRaw)

		var specializationPtr *string
		if includeSpecialization {
			specializationPtr = &specialization
		}

		in := &CreateBrigadeInput{
			DepartmentID:   departmentID,
			Name:           name,
			Description:    description,
			Specialization: specializationPtr,
		}

		err := in.Validate()

		if departmentID == uuid.Nil && err == nil {
			t.Fatal("empty department_id should be invalid")
		}
		if strings.TrimSpace(name) == "" && err == nil {
			t.Fatal("empty name should be invalid")
		}
	})
}

func FuzzListBrigadesInputValidate(f *testing.F) {
	departmentID := uuid.New().String()

	f.Add(departmentID, "ACTIVE", "roads", "created_at", "desc", int32(20), int32(0))
	f.Add("", "", "", "", "", int32(0), int32(-10))
	f.Add("bad-id", "BAD", strings.Repeat("a", 256), "bad", "bad", int32(500), int32(-100))
	f.Add(uuid.Nil.String(), "ARCHIVED", "water", "name", "asc", int32(10), int32(5))

	f.Fuzz(func(t *testing.T, departmentIDRaw string, statusRaw string, specialization string, sortByRaw string, sortOrderRaw string, limit int32, offset int32) {
		var departmentIDPtr *uuid.UUID
		if departmentIDRaw != "" {
			departmentID, _ := uuid.Parse(departmentIDRaw)
			departmentIDPtr = &departmentID
		}

		var statusPtr *BrigadeStatus
		if statusRaw != "" {
			value := BrigadeStatus(statusRaw)
			statusPtr = &value
		}

		var specializationPtr *string
		if specialization != "" {
			specializationPtr = &specialization
		}

		in := &ListBrigadesInput{
			DepartmentID:   departmentIDPtr,
			Status:         statusPtr,
			Specialization: specializationPtr,
			SortBy:         BrigadeSortBy(sortByRaw),
			SortOrder:      SortOrder(sortOrderRaw),
			Limit:          limit,
			Offset:         offset,
		}

		_ = in.Validate()
	})
}

func FuzzUpdateBrigadeInputValidate(f *testing.F) {
	brigadeID := uuid.New().String()

	f.Add(brigadeID, "South crew", "Updated", "water", true, true, true)
	f.Add("", "", "", "", false, false, false)
	f.Add("bad-id", strings.Repeat("a", 256), strings.Repeat("a", 1001), strings.Repeat("a", 256), true, true, true)
	f.Add(uuid.Nil.String(), "Crew", "", "", true, false, false)

	f.Fuzz(func(t *testing.T, brigadeIDRaw string, name string, description string, specialization string, includeName bool, includeDescription bool, includeSpecialization bool) {
		brigadeID, _ := uuid.Parse(brigadeIDRaw)

		var namePtr *string
		if includeName {
			namePtr = &name
		}

		var descriptionPtr *string
		if includeDescription {
			descriptionPtr = &description
		}

		var specializationPtr *string
		if includeSpecialization {
			specializationPtr = &specialization
		}

		in := &UpdateBrigadeInput{
			ID:             brigadeID,
			Name:           namePtr,
			Description:    descriptionPtr,
			Specialization: specializationPtr,
		}

		err := in.Validate()

		if brigadeID == uuid.Nil && err == nil {
			t.Fatal("empty id should be invalid")
		}
		if namePtr == nil && descriptionPtr == nil && specializationPtr == nil && err == nil {
			t.Fatal("update without fields should be invalid")
		}
	})
}

func FuzzSetBrigadeStatusInputValidate(f *testing.F) {
	brigadeID := uuid.New().String()

	f.Add(brigadeID, "ACTIVE")
	f.Add("", "")
	f.Add("bad-id", "BAD")
	f.Add(uuid.Nil.String(), "AVAILABLE")

	f.Fuzz(func(t *testing.T, brigadeIDRaw string, statusRaw string) {
		brigadeID, _ := uuid.Parse(brigadeIDRaw)

		in := &SetBrigadeStatusInput{
			BrigadeID: brigadeID,
			Status:    BrigadeStatus(statusRaw),
		}

		err := in.Validate()

		if brigadeID == uuid.Nil && err == nil {
			t.Fatal("empty brigade_id should be invalid")
		}
	})
}

func FuzzAddBrigadeMemberInputValidate(f *testing.F) {
	brigadeID := uuid.New().String()
	userID := uuid.New().String()
	profileID := uuid.New().String()

	f.Add(brigadeID, userID, profileID, "LEAD", true)
	f.Add("", "", "", "", false)
	f.Add("bad-id", "bad-user", "bad-profile", "BAD", true)
	f.Add(uuid.Nil.String(), uuid.Nil.String(), uuid.Nil.String(), "DRIVER", true)

	f.Fuzz(func(t *testing.T, brigadeIDRaw string, userIDRaw string, profileIDRaw string, roleRaw string, includeProfileID bool) {
		brigadeID, _ := uuid.Parse(brigadeIDRaw)
		userID, _ := uuid.Parse(userIDRaw)

		var profileIDPtr *uuid.UUID
		if includeProfileID {
			profileID, _ := uuid.Parse(profileIDRaw)
			profileIDPtr = &profileID
		}

		in := &AddBrigadeMemberInput{
			BrigadeID: brigadeID,
			UserID:    userID,
			ProfileID: profileIDPtr,
			Role:      BrigadeMemberRole(roleRaw),
		}

		err := in.Validate()

		if brigadeID == uuid.Nil && err == nil {
			t.Fatal("empty brigade_id should be invalid")
		}
		if userID == uuid.Nil && err == nil {
			t.Fatal("empty user_id should be invalid")
		}
	})
}

func FuzzChangeBrigadeMemberRoleInputValidate(f *testing.F) {
	brigadeID := uuid.New().String()
	memberID := uuid.New().String()

	f.Add(brigadeID, memberID, "DRIVER")
	f.Add("", "", "")
	f.Add("bad-id", "bad-member", "BAD")
	f.Add(uuid.Nil.String(), uuid.Nil.String(), "LEAD")

	f.Fuzz(func(t *testing.T, brigadeIDRaw string, memberIDRaw string, roleRaw string) {
		brigadeID, _ := uuid.Parse(brigadeIDRaw)
		memberID, _ := uuid.Parse(memberIDRaw)

		in := &ChangeBrigadeMemberRoleInput{
			BrigadeID: brigadeID,
			MemberID:  memberID,
			Role:      BrigadeMemberRole(roleRaw),
		}

		err := in.Validate()

		if brigadeID == uuid.Nil && err == nil {
			t.Fatal("empty brigade_id should be invalid")
		}
		if memberID == uuid.Nil && err == nil {
			t.Fatal("empty member_id should be invalid")
		}
	})
}

func FuzzSetBrigadeScheduleInputValidate(f *testing.F) {
	brigadeID := uuid.New().String()

	f.Add(brigadeID, int16(1), "09:00", "18:00", "UTC", true)
	f.Add("", int16(0), "", "", "", true)
	f.Add("bad-id", int16(8), "09:00", "09:00", strings.Repeat("a", 65), true)
	f.Add(uuid.Nil.String(), int16(7), "22:00", "06:00", "Europe/Moscow", false)

	f.Fuzz(func(t *testing.T, brigadeIDRaw string, dayOfWeek int16, startsAt string, endsAt string, timezone string, includeItem bool) {
		brigadeID, _ := uuid.Parse(brigadeIDRaw)

		items := []*BrigadeScheduleItem{}
		if includeItem {
			items = append(items, &BrigadeScheduleItem{
				DayOfWeek: dayOfWeek,
				StartsAt:  startsAt,
				EndsAt:    endsAt,
				Timezone:  timezone,
			})
		}

		in := &SetBrigadeScheduleInput{
			BrigadeID: brigadeID,
			Items:     items,
		}

		err := in.Validate()

		if brigadeID == uuid.Nil && err == nil {
			t.Fatal("empty brigade_id should be invalid")
		}
		if len(items) == 0 && err == nil {
			t.Fatal("empty schedule items should be invalid")
		}
	})
}

func FuzzCreateBrigadeZoneInputValidate(f *testing.F) {
	brigadeID := uuid.New().String()
	departmentID := uuid.New().String()

	f.Add(brigadeID, departmentID, "North", `{"type":"Polygon","coordinates":[]}`, int32(1))
	f.Add("", "", "", "", int32(0))
	f.Add("bad-id", "bad-department", strings.Repeat("a", 256), "", int32(-1))
	f.Add(uuid.Nil.String(), uuid.Nil.String(), "Зона", "{}", int32(10))

	f.Fuzz(func(t *testing.T, brigadeIDRaw string, departmentIDRaw string, name string, geoJSON string, priority int32) {
		brigadeID, _ := uuid.Parse(brigadeIDRaw)
		departmentID, _ := uuid.Parse(departmentIDRaw)

		in := &CreateBrigadeZoneInput{
			BrigadeID:    brigadeID,
			DepartmentID: departmentID,
			Name:         name,
			GeoJSON:      geoJSON,
			Priority:     priority,
		}

		err := in.Validate()

		if brigadeID == uuid.Nil && err == nil {
			t.Fatal("empty brigade_id should be invalid")
		}
		if departmentID == uuid.Nil && err == nil {
			t.Fatal("empty department_id should be invalid")
		}
		if strings.TrimSpace(name) == "" && err == nil {
			t.Fatal("empty name should be invalid")
		}
	})
}

func FuzzCheckBrigadeCanHandleTicketInputValidate(f *testing.F) {
	brigadeID := uuid.New().String()
	departmentID := uuid.New().String()
	skillID := uuid.New().String()

	f.Add(brigadeID, departmentID, 37.618423, 55.751244, skillID, "LEAD", true, true)
	f.Add("", "", 0.0, 0.0, "", "", false, false)
	f.Add("bad-id", "bad-department", 181.0, 91.0, "bad-skill", "BAD", true, true)
	f.Add(uuid.Nil.String(), uuid.Nil.String(), -181.0, -91.0, uuid.Nil.String(), "DRIVER", true, true)

	f.Fuzz(func(t *testing.T, brigadeIDRaw string, departmentIDRaw string, longitude float64, latitude float64, skillIDRaw string, roleRaw string, includeSkill bool, includeRole bool) {
		brigadeID, _ := uuid.Parse(brigadeIDRaw)
		departmentID, _ := uuid.Parse(departmentIDRaw)

		requiredSkillIDs := []uuid.UUID{}
		if includeSkill {
			skillID, _ := uuid.Parse(skillIDRaw)
			requiredSkillIDs = append(requiredSkillIDs, skillID)
		}

		requiredRoles := []BrigadeMemberRole{}
		if includeRole {
			requiredRoles = append(requiredRoles, BrigadeMemberRole(roleRaw))
		}

		in := &CheckBrigadeCanHandleTicketInput{
			BrigadeID:        brigadeID,
			DepartmentID:     departmentID,
			Longitude:        longitude,
			Latitude:         latitude,
			RequiredSkillIDs: requiredSkillIDs,
			RequiredRoles:    requiredRoles,
		}

		err := in.Validate()

		if brigadeID == uuid.Nil && err == nil {
			t.Fatal("empty brigade_id should be invalid")
		}
		if departmentID == uuid.Nil && err == nil {
			t.Fatal("empty department_id should be invalid")
		}
	})
}
