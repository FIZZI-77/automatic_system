package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCreateBrigadeInputValidate(t *testing.T) {
	departmentID := uuid.New()
	long := repeatString("a", 256)

	tests := []struct {
		name    string
		input   *CreateBrigadeInput
		wantErr bool
	}{
		{name: "valid", input: &CreateBrigadeInput{DepartmentID: departmentID, Name: "North crew"}, wantErr: false},
		{name: "nil", input: nil, wantErr: true},
		{name: "empty department", input: &CreateBrigadeInput{DepartmentID: uuid.Nil, Name: "North crew"}, wantErr: true},
		{name: "empty name", input: &CreateBrigadeInput{DepartmentID: departmentID, Name: ""}, wantErr: true},
		{name: "long specialization", input: &CreateBrigadeInput{DepartmentID: departmentID, Name: "North crew", Specialization: &long}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			assertValidationError(t, err, tt.wantErr)
		})
	}
}

func TestListBrigadesInputValidate(t *testing.T) {
	departmentID := uuid.New()
	now := time.Now()
	before := now.Add(-time.Hour)
	invalidStatus := BrigadeStatus("BAD")
	emptyDepartment := uuid.Nil

	tests := []struct {
		name    string
		input   *ListBrigadesInput
		wantErr bool
	}{
		{name: "valid defaults", input: &ListBrigadesInput{}, wantErr: false},
		{name: "valid filters", input: &ListBrigadesInput{DepartmentID: &departmentID, Status: ptrBrigadeStatus(BrigadeStatusActive), CreatedFrom: &before, CreatedTo: &now, SortBy: BrigadeSortByName, SortOrder: SortOrderAsc}, wantErr: false},
		{name: "nil", input: nil, wantErr: true},
		{name: "empty department", input: &ListBrigadesInput{DepartmentID: &emptyDepartment}, wantErr: true},
		{name: "invalid status", input: &ListBrigadesInput{Status: &invalidStatus}, wantErr: true},
		{name: "invalid range", input: &ListBrigadesInput{CreatedFrom: &now, CreatedTo: &before}, wantErr: true},
		{name: "invalid sort by", input: &ListBrigadesInput{SortBy: BrigadeSortBy("bad")}, wantErr: true},
		{name: "invalid sort order", input: &ListBrigadesInput{SortOrder: SortOrder("bad")}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			assertValidationError(t, err, tt.wantErr)
		})
	}
}

func TestUpdateBrigadeInputValidate(t *testing.T) {
	id := uuid.New()
	name := "South crew"
	blank := "   "

	tests := []struct {
		name    string
		input   *UpdateBrigadeInput
		wantErr bool
	}{
		{name: "valid", input: &UpdateBrigadeInput{ID: id, Name: &name}, wantErr: false},
		{name: "nil", input: nil, wantErr: true},
		{name: "empty id", input: &UpdateBrigadeInput{ID: uuid.Nil, Name: &name}, wantErr: true},
		{name: "blank name", input: &UpdateBrigadeInput{ID: id, Name: &blank}, wantErr: true},
		{name: "no fields", input: &UpdateBrigadeInput{ID: id}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			assertValidationError(t, err, tt.wantErr)
		})
	}
}

func TestBrigadeStatusInputsValidate(t *testing.T) {
	brigadeID := uuid.New()
	invalidStatus := BrigadeStatus("BAD")

	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{name: "deactivate valid", err: (&DeactivateBrigadeInput{ID: brigadeID}).Validate(), wantErr: false},
		{name: "deactivate empty id", err: (&DeactivateBrigadeInput{ID: uuid.Nil}).Validate(), wantErr: true},
		{name: "archive valid", err: (&ArchiveBrigadeInput{ID: brigadeID}).Validate(), wantErr: false},
		{name: "archive empty id", err: (&ArchiveBrigadeInput{ID: uuid.Nil}).Validate(), wantErr: true},
		{name: "set status valid", err: (&SetBrigadeStatusInput{BrigadeID: brigadeID, Status: BrigadeStatusActive}).Validate(), wantErr: false},
		{name: "set status invalid", err: (&SetBrigadeStatusInput{BrigadeID: brigadeID, Status: invalidStatus}).Validate(), wantErr: true},
		{name: "status history valid", err: (&GetBrigadeStatusHistoryInput{BrigadeID: brigadeID}).Validate(), wantErr: false},
		{name: "status history empty id", err: (&GetBrigadeStatusHistoryInput{BrigadeID: uuid.Nil}).Validate(), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidationError(t, tt.err, tt.wantErr)
		})
	}
}

func TestMemberInputsValidate(t *testing.T) {
	brigadeID := uuid.New()
	memberID := uuid.New()
	userID := uuid.New()
	invalidRole := BrigadeMemberRole("BAD")
	invalidAvailability := BrigadeMemberAvailabilityStatus("BAD")

	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{name: "add valid", err: (&AddBrigadeMemberInput{BrigadeID: brigadeID, UserID: userID, Role: BrigadeMemberRoleLead}).Validate(), wantErr: false},
		{name: "add invalid role", err: (&AddBrigadeMemberInput{BrigadeID: brigadeID, UserID: userID, Role: invalidRole}).Validate(), wantErr: true},
		{name: "remove valid", err: (&RemoveBrigadeMemberInput{BrigadeID: brigadeID, MemberID: memberID}).Validate(), wantErr: false},
		{name: "change role valid", err: (&ChangeBrigadeMemberRoleInput{BrigadeID: brigadeID, MemberID: memberID, Role: BrigadeMemberRoleDriver}).Validate(), wantErr: false},
		{name: "availability valid", err: (&SetBrigadeMemberAvailabilityInput{BrigadeID: brigadeID, MemberID: memberID, Status: BrigadeMemberAvailabilityAvailable}).Validate(), wantErr: false},
		{name: "availability invalid", err: (&SetBrigadeMemberAvailabilityInput{BrigadeID: brigadeID, MemberID: memberID, Status: invalidAvailability}).Validate(), wantErr: true},
		{name: "list valid", err: (&ListBrigadeMembersInput{BrigadeID: brigadeID}).Validate(), wantErr: false},
		{name: "list invalid role", err: (&ListBrigadeMembersInput{BrigadeID: brigadeID, Role: &invalidRole}).Validate(), wantErr: true},
		{name: "history valid", err: (&GetBrigadeMemberHistoryInput{BrigadeID: brigadeID}).Validate(), wantErr: false},
		{name: "status history valid", err: (&GetBrigadeMemberStatusHistoryInput{BrigadeID: brigadeID}).Validate(), wantErr: false},
		{name: "by user valid", err: (&GetBrigadeByUserIDInput{UserID: userID}).Validate(), wantErr: false},
		{name: "by user empty", err: (&GetBrigadeByUserIDInput{UserID: uuid.Nil}).Validate(), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidationError(t, tt.err, tt.wantErr)
		})
	}
}

func TestSkillInputsValidate(t *testing.T) {
	id := uuid.New()
	code := "electric"
	name := "Electric"
	active := true

	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{name: "create valid", err: (&CreateSkillInput{Code: code, Name: name}).Validate(), wantErr: false},
		{name: "create empty code", err: (&CreateSkillInput{Code: "", Name: name}).Validate(), wantErr: true},
		{name: "update valid code", err: (&UpdateSkillInput{ID: id, Code: &code}).Validate(), wantErr: false},
		{name: "update valid active", err: (&UpdateSkillInput{ID: id, Active: &active}).Validate(), wantErr: false},
		{name: "update no fields", err: (&UpdateSkillInput{ID: id}).Validate(), wantErr: true},
		{name: "deactivate valid", err: (&DeactivateSkillInput{ID: id}).Validate(), wantErr: false},
		{name: "list valid", err: (&ListSkillsInput{}).Validate(), wantErr: false},
		{name: "add brigade skill valid", err: (&AddBrigadeSkillInput{BrigadeID: uuid.New(), SkillID: id}).Validate(), wantErr: false},
		{name: "remove brigade skill valid", err: (&RemoveBrigadeSkillInput{BrigadeID: uuid.New(), SkillID: id}).Validate(), wantErr: false},
		{name: "list brigade skills valid", err: (&ListBrigadeSkillsInput{BrigadeID: uuid.New()}).Validate(), wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidationError(t, tt.err, tt.wantErr)
		})
	}
}

func TestScheduleInputsValidate(t *testing.T) {
	brigadeID := uuid.New()
	from := time.Now()
	to := from.Add(-time.Hour)

	tests := []struct {
		name    string
		input   *SetBrigadeScheduleInput
		wantErr bool
	}{
		{name: "valid", input: &SetBrigadeScheduleInput{BrigadeID: brigadeID, Items: []*BrigadeScheduleItem{{DayOfWeek: 1, StartsAt: "09:00", EndsAt: "18:00", Timezone: "UTC"}}}, wantErr: false},
		{name: "empty items", input: &SetBrigadeScheduleInput{BrigadeID: brigadeID}, wantErr: true},
		{name: "nil item", input: &SetBrigadeScheduleInput{BrigadeID: brigadeID, Items: []*BrigadeScheduleItem{nil}}, wantErr: true},
		{name: "bad day", input: &SetBrigadeScheduleInput{BrigadeID: brigadeID, Items: []*BrigadeScheduleItem{{DayOfWeek: 8, StartsAt: "09:00", EndsAt: "18:00"}}}, wantErr: true},
		{name: "same time", input: &SetBrigadeScheduleInput{BrigadeID: brigadeID, Items: []*BrigadeScheduleItem{{DayOfWeek: 1, StartsAt: "09:00", EndsAt: "09:00"}}}, wantErr: true},
		{name: "bad valid range", input: &SetBrigadeScheduleInput{BrigadeID: brigadeID, Items: []*BrigadeScheduleItem{{DayOfWeek: 1, StartsAt: "09:00", EndsAt: "18:00", ValidFrom: &from, ValidTo: &to}}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			assertValidationError(t, err, tt.wantErr)
		})
	}
}

func TestZoneAndAvailabilityInputsValidate(t *testing.T) {
	brigadeID := uuid.New()
	departmentID := uuid.New()
	skillID := uuid.New()
	invalidRole := BrigadeMemberRole("BAD")

	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{name: "create zone valid", err: (&CreateBrigadeZoneInput{BrigadeID: brigadeID, DepartmentID: departmentID, Name: "North", GeoJSON: "{}"}).Validate(), wantErr: false},
		{name: "create zone empty geo", err: (&CreateBrigadeZoneInput{BrigadeID: brigadeID, DepartmentID: departmentID, Name: "North", GeoJSON: ""}).Validate(), wantErr: true},
		{name: "update zone valid", err: (&UpdateBrigadeZoneInput{ID: uuid.New(), Name: ptrString("South")}).Validate(), wantErr: false},
		{name: "update zone no fields", err: (&UpdateBrigadeZoneInput{ID: uuid.New()}).Validate(), wantErr: true},
		{name: "delete zone valid", err: (&DeleteBrigadeZoneInput{ID: uuid.New()}).Validate(), wantErr: false},
		{name: "list zones valid", err: (&ListBrigadeZonesInput{BrigadeID: brigadeID}).Validate(), wantErr: false},
		{name: "covers point valid", err: (&CheckBrigadeCoversPointInput{BrigadeID: brigadeID, Longitude: 37.62, Latitude: 55.75}).Validate(), wantErr: false},
		{name: "covers point bad longitude", err: (&CheckBrigadeCoversPointInput{BrigadeID: brigadeID, Longitude: 181, Latitude: 55.75}).Validate(), wantErr: true},
		{name: "find by point valid", err: (&FindBrigadesByPointInput{DepartmentID: departmentID, Longitude: 37.62, Latitude: 55.75}).Validate(), wantErr: false},
		{name: "find by point invalid role", err: (&FindBrigadesByPointInput{DepartmentID: departmentID, Longitude: 37.62, Latitude: 55.75, RequiredRoles: []BrigadeMemberRole{invalidRole}}).Validate(), wantErr: true},
		{name: "available valid", err: (&GetAvailableBrigadesInput{DepartmentID: departmentID, RequiredSkillIDs: []uuid.UUID{skillID}}).Validate(), wantErr: false},
		{name: "available missing latitude", err: (&GetAvailableBrigadesInput{DepartmentID: departmentID, Longitude: ptrFloat64(37.62)}).Validate(), wantErr: true},
		{name: "can handle valid", err: (&CheckBrigadeCanHandleTicketInput{BrigadeID: brigadeID, DepartmentID: departmentID, Longitude: 37.62, Latitude: 55.75}).Validate(), wantErr: false},
		{name: "can handle nil skill", err: (&CheckBrigadeCanHandleTicketInput{BrigadeID: brigadeID, DepartmentID: departmentID, Longitude: 37.62, Latitude: 55.75, RequiredSkillIDs: []uuid.UUID{uuid.Nil}}).Validate(), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidationError(t, tt.err, tt.wantErr)
		})
	}
}

func TestListInputValidate_NormalizesLimitOffset(t *testing.T) {
	in := &ListBrigadesInput{Limit: 500, Offset: -10}

	err := in.Validate()
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if in.Limit != MaxLimit {
		t.Fatalf("expected limit %d, got %d", MaxLimit, in.Limit)
	}
	if in.Offset != 0 {
		t.Fatalf("expected offset 0, got %d", in.Offset)
	}
}

func ptrBrigadeStatus(status BrigadeStatus) *BrigadeStatus {
	return &status
}

func ptrString(value string) *string {
	return &value
}

func ptrFloat64(value float64) *float64 {
	return &value
}

func repeatString(value string, count int) string {
	out := ""
	for i := 0; i < count; i++ {
		out += value
	}
	return out
}

func assertValidationError(t *testing.T, err error, wantErr bool) {
	t.Helper()

	if wantErr && err == nil {
		t.Fatal("expected error, got nil")
	}
	if !wantErr && err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}
