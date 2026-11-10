package models

import (
	"time"

	"github.com/google/uuid"
)

// TicketIntegration описывает доменную модель.
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

// RegisterIntegrationInput задаёт входные данные операции.
type RegisterIntegrationInput struct {
	Name                string
	ClientID            string
	AllowedDepartmentID *uuid.UUID
	CreatedBy           uuid.UUID
	ActorRoles          []string
}

// RegisterIntegrationResult содержит результат операции.
type RegisterIntegrationResult struct {
	Integration *TicketIntegration
	Secret      string
}

// ListIntegrationsInput задаёт входные данные операции.
type ListIntegrationsInput struct {
	Limit      int32
	Offset     int32
	ActorRoles []string
}

// ListIntegrationsResult содержит результат операции.
type ListIntegrationsResult struct {
	Integrations []*TicketIntegration
	Total        int64
}

// SetIntegrationActiveInput задаёт входные данные операции.
type SetIntegrationActiveInput struct {
	IntegrationID uuid.UUID
	IsActive      bool
	ActorRoles    []string
}

// RotateIntegrationSecretInput задаёт входные данные операции.
type RotateIntegrationSecretInput struct {
	IntegrationID uuid.UUID
	ActorRoles    []string
}

// AuthenticateIntegrationInput задаёт входные данные операции.
type AuthenticateIntegrationInput struct {
	ClientID string
	Secret   string
}

// CreateExternalRequestInput задаёт входные данные операции.
type CreateExternalRequestInput struct {
	ClientID   string
	Secret     string
	ExternalID string
	Request    CreateRequestInput
}
