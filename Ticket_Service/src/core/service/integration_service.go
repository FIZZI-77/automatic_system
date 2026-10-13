package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"ticket/models"
	"ticket/src/core/repository"
)

const integrationSecretPrefix = "tki_"

type IntegrationService interface {
	RegisterIntegration(ctx context.Context, in *models.RegisterIntegrationInput) (*models.RegisterIntegrationResult, error)
	CreateExternalRequest(ctx context.Context, in *models.CreateExternalRequestInput) (*models.CreateRequestResult, error)
}

type IntegrationServiceStruct struct {
	repo *repository.Repository
}

func NewIntegrationServiceStruct(repo *repository.Repository) *IntegrationServiceStruct {
	return &IntegrationServiceStruct{repo: repo}
}

func (s *IntegrationServiceStruct) RegisterIntegration(
	ctx context.Context,
	in *models.RegisterIntegrationInput,
) (*models.RegisterIntegrationResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: RegisterIntegration(): %w: %v", models.ErrValidation, err)
	}

	if !hasRole(in.ActorRoles, "admin") {
		return nil, fmt.Errorf("service: RegisterIntegration(): %w", models.ErrPermissionDenied)
	}

	secret, err := newIntegrationSecret()

	if err != nil {
		return nil, fmt.Errorf("service: RegisterIntegration(): generate secret: %w", err)
	}

	secretHash := hashIntegrationSecret(secret)
	secretPrefix := secret[:min(len(secret), 12)]

	integration, err := s.repo.RegisterIntegration(ctx, in, secretHash, secretPrefix)

	if err != nil {
		return nil, fmt.Errorf("service: RegisterIntegration(): %w", err)
	}

	return &models.RegisterIntegrationResult{
		Integration: integration,
		Secret:      secret,
	}, nil
}

func (s *IntegrationServiceStruct) CreateExternalRequest(
	ctx context.Context,
	in *models.CreateExternalRequestInput,
) (*models.CreateRequestResult, error) {
	if in == nil {
		return nil, fmt.Errorf("service: CreateExternalRequest(): %w: input is nil", models.ErrValidation)
	}

	auth := &models.AuthenticateIntegrationInput{
		ClientID: strings.TrimSpace(in.ClientID),
		Secret:   strings.TrimSpace(in.Secret),
	}

	if err := auth.Validate(); err != nil {
		return nil, fmt.Errorf("service: CreateExternalRequest(): %w: %v", models.ErrValidation, err)
	}

	if strings.TrimSpace(in.ExternalID) == "" {
		return nil, fmt.Errorf("service: CreateExternalRequest(): %w: external_id is required", models.ErrValidation)
	}

	credential, err := s.repo.GetIntegrationCredential(ctx, auth.ClientID)

	if err != nil {
		return nil, fmt.Errorf("service: CreateExternalRequest(): %w", models.ErrIntegrationCredentials)
	}

	if !credential.Integration.IsActive {
		return nil, fmt.Errorf("service: CreateExternalRequest(): %w", models.ErrIntegrationInactive)
	}

	presentedHash := hashIntegrationSecret(auth.Secret)

	if subtle.ConstantTimeCompare([]byte(presentedHash), []byte(credential.SecretHash)) != 1 {
		return nil, fmt.Errorf("service: CreateExternalRequest(): %w", models.ErrIntegrationCredentials)
	}

	if credential.Integration.AllowedDepartmentID != nil &&
		*credential.Integration.AllowedDepartmentID != in.Request.DepartmentID {
		return nil, fmt.Errorf("service: CreateExternalRequest(): %w", models.ErrPermissionDenied)
	}

	externalID := strings.TrimSpace(in.ExternalID)
	in.Request.ExternalSystemID = &credential.Integration.ID
	in.Request.ExternalID = &externalID

	if err = in.Request.Validate(); err != nil {
		return nil, fmt.Errorf("service: CreateExternalRequest(): %w: %v", models.ErrValidation, err)
	}

	result, err := s.repo.CreateRequest(ctx, &in.Request)

	if err != nil {
		return nil, fmt.Errorf("service: CreateExternalRequest(): %w", err)
	}

	_ = s.repo.MarkIntegrationUsed(ctx, credential.Integration.ID)

	return result, nil
}

func newIntegrationSecret() (string, error) {
	value := make([]byte, 32)

	if _, err := rand.Read(value); err != nil {
		return "", err
	}

	return integrationSecretPrefix + base64.RawURLEncoding.EncodeToString(value), nil
}

func hashIntegrationSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))

	return hex.EncodeToString(sum[:])
}
