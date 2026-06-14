package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCreateDepartmentInputValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   *CreateDepartmentInput
		wantErr bool
	}{
		{name: "valid", input: &CreateDepartmentInput{Name: "Roads"}, wantErr: false},
		{name: "nil", input: nil, wantErr: true},
		{name: "empty name", input: &CreateDepartmentInput{Name: ""}, wantErr: true},
		{name: "spaces name", input: &CreateDepartmentInput{Name: "   "}, wantErr: true},
		{name: "long name", input: &CreateDepartmentInput{Name: repeatString("a", 256)}, wantErr: true},
		{name: "long description", input: &CreateDepartmentInput{Name: "Roads", Description: repeatString("a", 1001)}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			assertValidationError(t, err, tt.wantErr)
		})
	}
}

func TestGetDepartmentByIDInputValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   *GetDepartmentByIDInput
		wantErr bool
	}{
		{name: "valid", input: &GetDepartmentByIDInput{ID: uuid.New()}, wantErr: false},
		{name: "nil", input: nil, wantErr: true},
		{name: "empty id", input: &GetDepartmentByIDInput{ID: uuid.Nil}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			assertValidationError(t, err, tt.wantErr)
		})
	}
}

func TestListDepartmentsInputValidate(t *testing.T) {
	now := time.Now()
	before := now.Add(-time.Hour)
	invalidStatus := DepartmentStatus("BAD")

	tests := []struct {
		name    string
		input   *ListDepartmentsInput
		wantErr bool
	}{
		{name: "valid defaults", input: &ListDepartmentsInput{}, wantErr: false},
		{name: "valid filters", input: &ListDepartmentsInput{Status: ptrDepartmentStatus(DepartmentStatusActive), CreatedFrom: &before, CreatedTo: &now, SortBy: DepartmentSortByName, SortOrder: SortOrderAsc, Limit: 10, Offset: 5}, wantErr: false},
		{name: "nil", input: nil, wantErr: true},
		{name: "invalid status", input: &ListDepartmentsInput{Status: &invalidStatus}, wantErr: true},
		{name: "invalid range", input: &ListDepartmentsInput{CreatedFrom: &now, CreatedTo: &before}, wantErr: true},
		{name: "invalid sort by", input: &ListDepartmentsInput{SortBy: DepartmentSortBy("bad")}, wantErr: true},
		{name: "invalid sort order", input: &ListDepartmentsInput{SortOrder: SortOrder("bad")}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			assertValidationError(t, err, tt.wantErr)
		})
	}
}

func TestListDepartmentsInputValidate_NormalizesLimitOffset(t *testing.T) {
	in := &ListDepartmentsInput{Limit: 500, Offset: -10}

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

func TestUpdateDepartmentInputValidate(t *testing.T) {
	validID := uuid.New()
	name := "Water"
	description := "Water service"
	status := DepartmentStatusInactive
	invalidStatus := DepartmentStatus("BAD")
	blank := "   "

	tests := []struct {
		name    string
		input   *UpdateDepartmentInput
		wantErr bool
	}{
		{name: "valid name", input: &UpdateDepartmentInput{ID: validID, Name: &name}, wantErr: false},
		{name: "valid description", input: &UpdateDepartmentInput{ID: validID, Description: &description}, wantErr: false},
		{name: "valid status", input: &UpdateDepartmentInput{ID: validID, Status: &status}, wantErr: false},
		{name: "nil", input: nil, wantErr: true},
		{name: "empty id", input: &UpdateDepartmentInput{ID: uuid.Nil, Name: &name}, wantErr: true},
		{name: "blank name", input: &UpdateDepartmentInput{ID: validID, Name: &blank}, wantErr: true},
		{name: "invalid status", input: &UpdateDepartmentInput{ID: validID, Status: &invalidStatus}, wantErr: true},
		{name: "no fields", input: &UpdateDepartmentInput{ID: validID}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			assertValidationError(t, err, tt.wantErr)
		})
	}
}

func TestDeleteDepartmentInputValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   *DeleteDepartmentInput
		wantErr bool
	}{
		{name: "valid", input: &DeleteDepartmentInput{ID: uuid.New()}, wantErr: false},
		{name: "nil", input: nil, wantErr: true},
		{name: "empty id", input: &DeleteDepartmentInput{ID: uuid.Nil}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			assertValidationError(t, err, tt.wantErr)
		})
	}
}

func ptrDepartmentStatus(status DepartmentStatus) *DepartmentStatus {
	return &status
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
