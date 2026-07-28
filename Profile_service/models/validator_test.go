package models

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestEnumValidation(t *testing.T) {
	if !PreferredContactMethodEmail.IsValid() || PreferredContactMethod("BAD").IsValid() {
		t.Fatal("preferred contact method validation is incorrect")
	}
	if !WorkProfileStatusActive.IsValid() || WorkProfileStatus("BAD").IsValid() {
		t.Fatal("work profile status validation is incorrect")
	}
	if !CanJoinBrigadeReasonNoWorkProfile.IsValid() || CanJoinBrigadeReason("BAD").IsValid() {
		t.Fatal("can join brigade reason validation is incorrect")
	}
	if !OutboxEventStatusPending.IsValid() || OutboxEventStatus("BAD").IsValid() {
		t.Fatal("outbox event status validation is incorrect")
	}
}

func TestCreateUserProfileInputValidate(t *testing.T) {
	phone := "+79991234567"
	badPhone := "89991234567"

	tests := []struct {
		name    string
		input   *CreateUserProfileInput
		wantErr bool
	}{
		{name: "valid defaults", input: &CreateUserProfileInput{UserID: uuid.New(), FullName: "Иван Иванов"}},
		{name: "valid phone contact", input: &CreateUserProfileInput{UserID: uuid.New(), FullName: "Иван Иванов", Phone: &phone, PreferredContactMethod: PreferredContactMethodPhone}},
		{name: "nil", input: nil, wantErr: true},
		{name: "missing user id", input: &CreateUserProfileInput{FullName: "Иван Иванов"}, wantErr: true},
		{name: "short full name", input: &CreateUserProfileInput{UserID: uuid.New(), FullName: "A"}, wantErr: true},
		{name: "long full name", input: &CreateUserProfileInput{UserID: uuid.New(), FullName: strings.Repeat("a", 256)}, wantErr: true},
		{name: "invalid phone", input: &CreateUserProfileInput{UserID: uuid.New(), FullName: "Иван Иванов", Phone: &badPhone}, wantErr: true},
		{name: "phone contact without phone", input: &CreateUserProfileInput{UserID: uuid.New(), FullName: "Иван Иванов", PreferredContactMethod: PreferredContactMethodPhone}, wantErr: true},
		{name: "invalid contact method", input: &CreateUserProfileInput{UserID: uuid.New(), FullName: "Иван Иванов", PreferredContactMethod: "SMS"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidation(t, tt.input.Validate(), tt.wantErr)
		})
	}

	in := &CreateUserProfileInput{UserID: uuid.New(), FullName: "Иван Иванов"}
	if err := in.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if in.PreferredContactMethod != PreferredContactMethodEmail {
		t.Fatalf("expected EMAIL default, got %s", in.PreferredContactMethod)
	}
}

func TestUpdateUserProfileInputValidate(t *testing.T) {
	name := "Петр Петров"
	phone := "+79991234567"
	avatarID := uuid.New()
	method := PreferredContactMethodPush

	tests := []struct {
		name    string
		input   *UpdateUserProfileInput
		wantErr bool
	}{
		{name: "valid name", input: &UpdateUserProfileInput{ID: uuid.New(), FullName: &name}},
		{name: "valid phone", input: &UpdateUserProfileInput{ID: uuid.New(), Phone: &phone}},
		{name: "valid clear phone", input: &UpdateUserProfileInput{ID: uuid.New(), ClearPhone: true}},
		{name: "valid avatar", input: &UpdateUserProfileInput{ID: uuid.New(), AvatarFileID: &avatarID}},
		{name: "valid method", input: &UpdateUserProfileInput{ID: uuid.New(), PreferredContactMethod: &method}},
		{name: "nil", input: nil, wantErr: true},
		{name: "missing id", input: &UpdateUserProfileInput{FullName: &name}, wantErr: true},
		{name: "no fields", input: &UpdateUserProfileInput{ID: uuid.New()}, wantErr: true},
		{name: "phone clear conflict", input: &UpdateUserProfileInput{ID: uuid.New(), Phone: &phone, ClearPhone: true}, wantErr: true},
		{name: "avatar clear conflict", input: &UpdateUserProfileInput{ID: uuid.New(), AvatarFileID: &avatarID, ClearAvatarFileID: true}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidation(t, tt.input.Validate(), tt.wantErr)
		})
	}
}

func TestListInputsValidate(t *testing.T) {
	userInput := &ListUserProfilesInput{Limit: 500, Offset: -1}
	if err := userInput.Validate(); err != nil {
		t.Fatalf("unexpected user list validation error: %v", err)
	}
	if userInput.Limit != MaxLimit || userInput.Offset != 0 || userInput.SortBy != UserProfileSortByCreatedAt || userInput.SortOrder != SortOrderDesc {
		t.Fatalf("user list defaults were not normalized: %+v", userInput)
	}

	workInput := &ListWorkProfilesInput{}
	if err := workInput.Validate(); err != nil {
		t.Fatalf("unexpected work list validation error: %v", err)
	}
	if workInput.Limit != DefaultLimit || workInput.SortBy != WorkProfileSortByCreatedAt || workInput.SortOrder != SortOrderDesc {
		t.Fatalf("work list defaults were not normalized: %+v", workInput)
	}

	invalidStatus := WorkProfileStatus("BAD")
	assertValidation(t, (&ListWorkProfilesInput{Status: &invalidStatus}).Validate(), true)
	assertValidation(t, (&ListUserProfilesInput{SortBy: "bad"}).Validate(), true)
	assertValidation(t, (&ListWorkProfilesInput{SortOrder: "bad"}).Validate(), true)
}

func TestCreateWorkProfileInputValidate(t *testing.T) {
	employeeNumber := "EMP-001"

	tests := []struct {
		name    string
		input   *CreateWorkProfileInput
		wantErr bool
	}{
		{name: "valid", input: &CreateWorkProfileInput{UserProfileID: uuid.New(), DepartmentID: uuid.New(), EmployeeNumber: &employeeNumber, Position: "Инженер"}},
		{name: "nil", input: nil, wantErr: true},
		{name: "missing user profile", input: &CreateWorkProfileInput{DepartmentID: uuid.New(), Position: "Инженер"}, wantErr: true},
		{name: "missing department", input: &CreateWorkProfileInput{UserProfileID: uuid.New(), Position: "Инженер"}, wantErr: true},
		{name: "blank position", input: &CreateWorkProfileInput{UserProfileID: uuid.New(), DepartmentID: uuid.New(), Position: " "}, wantErr: true},
		{name: "long employee number", input: &CreateWorkProfileInput{UserProfileID: uuid.New(), DepartmentID: uuid.New(), EmployeeNumber: stringPtr(strings.Repeat("a", 65)), Position: "Инженер"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidation(t, tt.input.Validate(), tt.wantErr)
		})
	}
}

func TestUpdateWorkProfileInputValidate(t *testing.T) {
	position := "Старший инженер"
	employeeNumber := "EMP-002"

	tests := []struct {
		name    string
		input   *UpdateWorkProfileInput
		wantErr bool
	}{
		{name: "valid position", input: &UpdateWorkProfileInput{ID: uuid.New(), Position: &position}},
		{name: "valid employee number", input: &UpdateWorkProfileInput{ID: uuid.New(), EmployeeNumber: &employeeNumber}},
		{name: "valid clear employee number", input: &UpdateWorkProfileInput{ID: uuid.New(), ClearEmployeeNumber: true}},
		{name: "nil", input: nil, wantErr: true},
		{name: "missing id", input: &UpdateWorkProfileInput{Position: &position}, wantErr: true},
		{name: "no fields", input: &UpdateWorkProfileInput{ID: uuid.New()}, wantErr: true},
		{name: "clear conflict", input: &UpdateWorkProfileInput{ID: uuid.New(), EmployeeNumber: &employeeNumber, ClearEmployeeNumber: true}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidation(t, tt.input.Validate(), tt.wantErr)
		})
	}
}

func TestWorkProfileOperationsValidate(t *testing.T) {
	assertValidation(t, (&DeactivateWorkProfileInput{ID: uuid.New(), Reason: "Уволен"}).Validate(), false)
	assertValidation(t, (&DeactivateWorkProfileInput{ID: uuid.New()}).Validate(), true)
	assertValidation(t, (&ChangeWorkProfileDepartmentInput{ID: uuid.New(), DepartmentID: uuid.New(), Reason: "Перевод"}).Validate(), false)
	assertValidation(t, (&ChangeWorkProfileDepartmentInput{ID: uuid.New(), Reason: "Перевод"}).Validate(), true)
	assertValidation(t, (&SetWorkProfileStatusInput{ID: uuid.New(), Status: WorkProfileStatusOnShift, Reason: "Начало смены"}).Validate(), false)
	assertValidation(t, (&SetWorkProfileStatusInput{ID: uuid.New(), Status: "BAD", Reason: "Причина"}).Validate(), true)
	assertValidation(t, (&GetWorkProfileStatusHistoryInput{WorkProfileID: uuid.New()}).Validate(), false)
	assertValidation(t, (&ResolveWorkingDepartmentInput{UserID: uuid.New()}).Validate(), false)
}

func TestCheckProfileCanJoinBrigadeInputValidate(t *testing.T) {
	userID := uuid.New()
	workProfileID := uuid.New()
	departmentID := uuid.New()

	tests := []struct {
		name    string
		input   *CheckProfileCanJoinBrigadeInput
		wantErr bool
	}{
		{name: "valid user id", input: &CheckProfileCanJoinBrigadeInput{UserID: &userID, BrigadeDepartmentID: departmentID}},
		{name: "valid work profile id", input: &CheckProfileCanJoinBrigadeInput{WorkProfileID: &workProfileID, BrigadeDepartmentID: departmentID}},
		{name: "nil", input: nil, wantErr: true},
		{name: "neither identifier", input: &CheckProfileCanJoinBrigadeInput{BrigadeDepartmentID: departmentID}, wantErr: true},
		{name: "both identifiers", input: &CheckProfileCanJoinBrigadeInput{UserID: &userID, WorkProfileID: &workProfileID, BrigadeDepartmentID: departmentID}, wantErr: true},
		{name: "missing department", input: &CheckProfileCanJoinBrigadeInput{UserID: &userID}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidation(t, tt.input.Validate(), tt.wantErr)
		})
	}
}

func stringPtr(value string) *string {
	return &value
}

func assertValidation(t *testing.T, err error, wantErr bool) {
	t.Helper()
	if wantErr && err == nil {
		t.Fatal("expected error, got nil")
	}
	if !wantErr && err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}
