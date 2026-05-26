package models

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func validCreateTicketInput() *CreateTicketInput {
	return &CreateTicketInput{
		DepartmentID: uuid.New(),
		CategoryID:   uuid.New(),
		UserID:       uuid.New(),
		Title:        "Pipe leak",
		Description:  "Pipe leak in basement",
		Priority:     TicketPriorityMedium,
		Address:      "Main street 1",
		Latitude:     55.751244,
		Longitude:    37.618423,
	}
}

func TestCreateTicketInput_Validate_CommonCases(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(in *CreateTicketInput)
		wantErr bool
	}{
		{
			name:    "valid",
			mutate:  func(in *CreateTicketInput) {},
			wantErr: false,
		},
		{
			name: "missing department",
			mutate: func(in *CreateTicketInput) {
				in.DepartmentID = uuid.Nil
			},
			wantErr: true,
		},
		{
			name: "empty title",
			mutate: func(in *CreateTicketInput) {
				in.Title = "   "
			},
			wantErr: true,
		},
		{
			name: "title too long",
			mutate: func(in *CreateTicketInput) {
				in.Title = strings.Repeat("a", 256)
			},
			wantErr: true,
		},
		{
			name: "invalid priority",
			mutate: func(in *CreateTicketInput) {
				in.Priority = TicketPriority("urgent")
			},
			wantErr: true,
		},
		{
			name: "invalid latitude",
			mutate: func(in *CreateTicketInput) {
				in.Latitude = 90.1
			},
			wantErr: true,
		},
		{
			name: "invalid longitude",
			mutate: func(in *CreateTicketInput) {
				in.Longitude = -180.1
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validCreateTicketInput()
			tt.mutate(in)

			err := in.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestListTicketsInput_Validate_NormalizesAndRejectsCommonCases(t *testing.T) {
	from := time.Now()
	to := from.Add(-time.Hour)
	invalidStatus := TicketStatus("OPEN")

	tests := []struct {
		name       string
		in         *ListTicketsInput
		wantErr    bool
		wantLimit  int32
		wantOffset int32
	}{
		{
			name:       "defaults limit offset and sorting",
			in:         &ListTicketsInput{},
			wantLimit:  DefaultLimit,
			wantOffset: 0,
		},
		{
			name:       "caps limit and normalizes negative offset",
			in:         &ListTicketsInput{Limit: 500, Offset: -10},
			wantLimit:  MaxLimit,
			wantOffset: 0,
		},
		{
			name:    "invalid status",
			in:      &ListTicketsInput{Status: &invalidStatus},
			wantErr: true,
		},
		{
			name:    "created_from after created_to",
			in:      &ListTicketsInput{CreatedFrom: &from, CreatedTo: &to},
			wantErr: true,
		},
		{
			name:    "nil input",
			in:      nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}

			if tt.wantErr {
				return
			}

			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}

			if tt.in.Limit != tt.wantLimit {
				t.Fatalf("expected limit %d, got %d", tt.wantLimit, tt.in.Limit)
			}

			if tt.in.Offset != tt.wantOffset {
				t.Fatalf("expected offset %d, got %d", tt.wantOffset, tt.in.Offset)
			}

			if tt.in.SortBy != TicketSortByCreatedAt {
				t.Fatalf("expected default sort_by created_at, got %s", tt.in.SortBy)
			}

			if tt.in.SortOrder != SortOrderDesc {
				t.Fatalf("expected default sort_order desc, got %s", tt.in.SortOrder)
			}
		})
	}
}

func TestUpdateTicketInput_Validate_CommonCases(t *testing.T) {
	validTitle := "Updated title"
	emptyTitle := "   "
	priority := TicketPriorityHigh
	invalidPriority := TicketPriority("critical")
	latitude := 55.7
	longitude := 37.6
	updatedBy := uuid.New()

	tests := []struct {
		name    string
		in      *UpdateTicketInput
		wantErr bool
	}{
		{
			name: "valid title only",
			in: &UpdateTicketInput{
				TicketID:  uuid.New(),
				Title:     &validTitle,
				UpdatedBy: &updatedBy,
			},
		},
		{
			name: "empty optional title",
			in: &UpdateTicketInput{
				TicketID:  uuid.New(),
				Title:     &emptyTitle,
				UpdatedBy: &updatedBy,
			},
			wantErr: true,
		},
		{
			name: "invalid priority",
			in: &UpdateTicketInput{
				TicketID:  uuid.New(),
				Priority:  &invalidPriority,
				UpdatedBy: &updatedBy,
			},
			wantErr: true,
		},
		{
			name: "valid priority",
			in: &UpdateTicketInput{
				TicketID:  uuid.New(),
				Priority:  &priority,
				UpdatedBy: &updatedBy,
			},
		},
		{
			name: "latitude without longitude",
			in: &UpdateTicketInput{
				TicketID:  uuid.New(),
				Latitude:  &latitude,
				UpdatedBy: &updatedBy,
			},
			wantErr: true,
		},
		{
			name: "valid coordinates",
			in: &UpdateTicketInput{
				TicketID:  uuid.New(),
				Latitude:  &latitude,
				Longitude: &longitude,
				UpdatedBy: &updatedBy,
			},
		},
		{
			name: "missing updated_by",
			in: &UpdateTicketInput{
				TicketID: uuid.New(),
				Title:    &validTitle,
			},
			wantErr: true,
		},
		{
			name:    "nil input",
			in:      nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestCategoryInputs_Validate_CommonCases(t *testing.T) {
	description := "description"
	name := "Updated"
	isActive := false

	tests := []struct {
		name    string
		run     func() error
		wantErr bool
	}{
		{
			name: "create valid",
			run: func() error {
				return (&CreateCategoryInput{Code: "water_supply", Name: "Water", Description: &description}).Validate()
			},
		},
		{
			name: "create rejects uppercase code",
			run: func() error {
				return (&CreateCategoryInput{Code: "Water", Name: "Water"}).Validate()
			},
			wantErr: true,
		},
		{
			name: "update name only",
			run: func() error {
				return (&UpdateCategoryInput{CategoryID: uuid.New(), Name: &name}).Validate()
			},
		},
		{
			name: "update explicit false only",
			run: func() error {
				return (&UpdateCategoryInput{CategoryID: uuid.New(), IsActive: &isActive}).Validate()
			},
		},
		{
			name: "update without fields",
			run: func() error {
				return (&UpdateCategoryInput{CategoryID: uuid.New()}).Validate()
			},
			wantErr: true,
		},
		{
			name: "delete missing id",
			run: func() error {
				return (&DeleteCategoryInput{}).Validate()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}
