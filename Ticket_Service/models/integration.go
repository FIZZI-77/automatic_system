package models

import (
	"time"

	"github.com/google/uuid"
)

type TicketIntegration struct {
	ID                  uuid.UUID  `json:"id"`
	Name                string     `json:"name"`
	ClientID            string     `json:"client_id"`
	SecretPrefix        string     `json:"secret_prefix"`
	AllowedDepartmentID *uuid.UUID `json:"allowed_department_id,omitempty"`
	IsActive            bool       `json:"is_active"`
	CreatedBy           uuid.UUID  `json:"created_by"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	LastUsedAt          *time.Time `json:"last_used_at,omitempty"`
}

type RegisterIntegrationInput struct {
	Name                string
	ClientID            string
	AllowedDepartmentID *uuid.UUID
	CreatedBy           uuid.UUID
	ActorRoles          []string
}

type RegisterIntegrationResult struct {
	Integration *TicketIntegration
	Secret      string
}

type AuthenticateIntegrationInput struct {
	ClientID string
	Secret   string
}

type CreateExternalRequestInput struct {
	ClientID   string
	Secret     string
	ExternalID string
	Request    CreateRequestInput
}
