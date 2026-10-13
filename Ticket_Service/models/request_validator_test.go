package models

import (
	"testing"

	"github.com/google/uuid"
)

func TestCreateRequestInputValidate(t *testing.T) {
	valid := validCreateRequestInput()

	if err := valid.Validate(); err != nil {
		t.Fatalf("CreateRequestInput.Validate(valid) error = %v, want nil", err)
	}

	externalID := "external-42"
	withoutSystem := validCreateRequestInput()
	withoutSystem.ExternalID = &externalID

	if err := withoutSystem.Validate(); err == nil {
		t.Error("CreateRequestInput.Validate(external ID without system) error = nil, want validation error")
	}

	externalSystemID := uuid.New()
	withoutExternalID := validCreateRequestInput()
	withoutExternalID.ExternalSystemID = &externalSystemID

	if err := withoutExternalID.Validate(); err == nil {
		t.Error("CreateRequestInput.Validate(external system without ID) error = nil, want validation error")
	}
}

func TestRegisterIntegrationInputValidate(t *testing.T) {
	in := &RegisterIntegrationInput{
		Name:       "Moscow city system",
		ClientID:   "mos_city_system",
		CreatedBy:  uuid.New(),
		ActorRoles: []string{"admin"},
	}

	if err := in.Validate(); err != nil {
		t.Fatalf("RegisterIntegrationInput.Validate(valid) error = %v, want nil", err)
	}

	in.ClientID = "A"

	if err := in.Validate(); err == nil {
		t.Error("RegisterIntegrationInput.Validate(invalid client ID) error = nil, want validation error")
	}
}

func TestTicketTypeIsValid(t *testing.T) {
	tests := []struct {
		name  string
		value TicketType
		want  bool
	}{
		{name: "incident", value: TicketTypeIncident, want: true},
		{name: "request", value: TicketTypeRequest, want: true},
		{name: "unknown", value: TicketType("UNKNOWN"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.value.IsValid(); got != tt.want {
				t.Errorf("TicketType(%q).IsValid() = %t, want %t", tt.value, got, tt.want)
			}
		})
	}
}

func validCreateRequestInput() *CreateRequestInput {
	return &CreateRequestInput{
		DepartmentID: uuid.New(),
		CategoryID:   uuid.New(),
		UserID:       uuid.New(),
		Title:        "Street light is not working",
		Description:  "Street light is not working near the building",
		Priority:     TicketPriorityMedium,
		Address:      "Main street 1",
		Latitude:     55.751244,
		Longitude:    37.618423,
	}
}
