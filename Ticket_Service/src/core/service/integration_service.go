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

	"github.com/google/uuid"

	"ticket/models"
	"ticket/src/core/repository"
)

const integrationSecretPrefix = "tki_"

type IntegrationService interface {
	// RegisterIntegration регистрирует внешний источник обращений; доступна только администратору.
	// Возвращает полный случайный секрет один раз, сохраняя в БД его хеш и префикс.
	// AllowedDepartmentID ограничивает источник одним департаментом.
	RegisterIntegration(ctx context.Context, in *models.RegisterIntegrationInput) (*models.RegisterIntegrationResult, error)
	// ListIntegrations возвращает страницу внешних источников и общее количество записей.
	// Требует роль admin, Limit от 1 до 100 и неотрицательный Offset; полные секреты не возвращает.
	ListIntegrations(ctx context.Context, in *models.ListIntegrationsInput) (*models.ListIntegrationsResult, error)
	// SetIntegrationActive включает или отключает внешний источник по IntegrationID.
	// Требует роль admin; отключённый источник не может создавать обращения.
	SetIntegrationActive(ctx context.Context, in *models.SetIntegrationActiveInput) (*models.TicketIntegration, error)
	// RotateIntegrationSecret заменяет секрет внешнего источника и один раз возвращает новый.
	// Требует роль admin. Старый хеш заменяется, а состояние активности сохраняется.
	RotateIntegrationSecret(ctx context.Context, in *models.RotateIntegrationSecretInput) (*models.RegisterIntegrationResult, error)
	// CreateExternalRequest создаёт обращение внешнего источника после проверки client_id и секрета.
	// Проверяет активность и разрешённый департамент; записывает идентификаторы источника
	// и обращения в in.Request. Ошибка обновления last_used_at не отменяет результат.
	CreateExternalRequest(ctx context.Context, in *models.CreateExternalRequestInput) (*models.CreateRequestResult, error)
}

type IntegrationServiceStruct struct {
	repo *repository.Repository
}

// NewIntegrationServiceStruct создаёт службу учётных данных внешних систем с общим репозиторием.
func NewIntegrationServiceStruct(repo *repository.Repository) *IntegrationServiceStruct {
	return &IntegrationServiceStruct{repo: repo}
}

// RegisterIntegration регистрирует внешний источник обращений; доступна только администратору.
// Возвращает полный случайный секрет один раз, сохраняя в БД его хеш и префикс.
// AllowedDepartmentID ограничивает источник одним департаментом.
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

// ListIntegrations возвращает страницу внешних источников и общее количество записей.
// Требует роль admin, Limit от 1 до 100 и неотрицательный Offset; полные секреты не возвращает.
func (s *IntegrationServiceStruct) ListIntegrations(
	ctx context.Context,
	in *models.ListIntegrationsInput,
) (*models.ListIntegrationsResult, error) {
	if in == nil || in.Limit < 1 || in.Limit > 100 || in.Offset < 0 {
		return nil, fmt.Errorf("service: ListIntegrations(): %w", models.ErrValidation)
	}

	if !hasRole(in.ActorRoles, "admin") {
		return nil, fmt.Errorf("service: ListIntegrations(): %w", models.ErrPermissionDenied)
	}

	integrations, total, err := s.repo.ListIntegrations(ctx, in.Limit, in.Offset)
	if err != nil {
		return nil, fmt.Errorf("service: ListIntegrations(): %w", err)
	}

	return &models.ListIntegrationsResult{Integrations: integrations, Total: total}, nil
}

// SetIntegrationActive включает или отключает внешний источник по IntegrationID.
// Требует роль admin; отключённый источник не может создавать обращения.
func (s *IntegrationServiceStruct) SetIntegrationActive(
	ctx context.Context,
	in *models.SetIntegrationActiveInput,
) (*models.TicketIntegration, error) {
	if in == nil || in.IntegrationID == uuid.Nil {
		return nil, fmt.Errorf("service: SetIntegrationActive(): %w", models.ErrValidation)
	}

	if !hasRole(in.ActorRoles, "admin") {
		return nil, fmt.Errorf("service: SetIntegrationActive(): %w", models.ErrPermissionDenied)
	}

	integration, err := s.repo.SetIntegrationActive(ctx, in.IntegrationID, in.IsActive)
	if err != nil {
		return nil, fmt.Errorf("service: SetIntegrationActive(): %w", err)
	}

	return integration, nil
}

// RotateIntegrationSecret заменяет секрет внешнего источника и один раз возвращает новый.
// Требует роль admin. Старый хеш заменяется, а состояние активности сохраняется.
func (s *IntegrationServiceStruct) RotateIntegrationSecret(
	ctx context.Context,
	in *models.RotateIntegrationSecretInput,
) (*models.RegisterIntegrationResult, error) {
	if in == nil || in.IntegrationID == uuid.Nil {
		return nil, fmt.Errorf("service: RotateIntegrationSecret(): %w", models.ErrValidation)
	}

	if !hasRole(in.ActorRoles, "admin") {
		return nil, fmt.Errorf("service: RotateIntegrationSecret(): %w", models.ErrPermissionDenied)
	}

	secret, err := newIntegrationSecret()
	if err != nil {
		return nil, fmt.Errorf("service: RotateIntegrationSecret(): generate secret: %w", err)
	}

	integration, err := s.repo.RotateIntegrationSecret(
		ctx,
		in.IntegrationID,
		hashIntegrationSecret(secret),
		secret[:min(len(secret), 12)],
	)
	if err != nil {
		return nil, fmt.Errorf("service: RotateIntegrationSecret(): %w", err)
	}

	return &models.RegisterIntegrationResult{Integration: integration, Secret: secret}, nil
}

// CreateExternalRequest создаёт обращение внешнего источника после проверки client_id и секрета.
// Проверяет активность и разрешённый департамент; записывает идентификаторы источника
// и обращения в in.Request. Ошибка обновления last_used_at не отменяет результат.
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

// newIntegrationSecret возвращает секрет tki_ из 32 криптографически случайных байтов.
// Возвращает ошибку, если системный источник случайности недоступен.
func newIntegrationSecret() (string, error) {
	value := make([]byte, 32)

	if _, err := rand.Read(value); err != nil {
		return "", err
	}

	return integrationSecretPrefix + base64.RawURLEncoding.EncodeToString(value), nil
}

// hashIntegrationSecret возвращает SHA-256 секрета в шестнадцатеричном виде для хранения и сравнения.
func hashIntegrationSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))

	return hex.EncodeToString(sum[:])
}
