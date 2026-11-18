package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"ticket/models"
)

type integrationCredential struct {
	Integration *models.TicketIntegration
	SecretHash  string
}

// RegisterIntegration сохраняет активный внешний источник с новым UUID.
// Принимает уже вычисленные хеш и префикс секрета; возвращает публичные метаданные.
func (r *Repository) RegisterIntegration(
	ctx context.Context,
	in *models.RegisterIntegrationInput,
	secretHash string,
	secretPrefix string,
) (*models.TicketIntegration, error) {
	const query = `
		INSERT INTO ticket_integrations (
			id,
			name,
			client_id,
			secret_hash,
			secret_prefix,
			allowed_department_id,
			is_active,
			created_by,
			created_at,
			updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7, now(), now())
		RETURNING
			id,
			name,
			client_id,
			secret_prefix,
			allowed_department_id,
			is_active,
			created_by,
			created_at,
			updated_at,
			last_used_at
	`

	row := r.writePool.QueryRow(
		ctx,
		query,
		uuid.New(),
		in.Name,
		in.ClientID,
		secretHash,
		secretPrefix,
		in.AllowedDepartmentID,
		in.CreatedBy,
	)

	integration, err := scanTicketIntegration(row)

	if err != nil {
		return nil, fmt.Errorf("repository: RegisterIntegration(): %w", err)
	}

	return integration, nil
}

// GetIntegrationCredential загружает источник по clientID вместе с хешем секрета.
// Используется для аутентификации; при отсутствии записи возвращает ErrNotFound.
func (r *Repository) GetIntegrationCredential(
	ctx context.Context,
	clientID string,
) (*integrationCredential, error) {
	const query = `
		SELECT
			id,
			name,
			client_id,
			secret_prefix,
			allowed_department_id,
			is_active,
			created_by,
			created_at,
			updated_at,
			last_used_at,
			secret_hash
		FROM ticket_integrations
		WHERE client_id = $1
	`

	credential, err := scanIntegrationCredential(r.readPool.QueryRow(ctx, query, clientID))

	if err != nil {
		return nil, fmt.Errorf("repository: GetIntegrationCredential(): %w", err)
	}

	return credential, nil
}

// MarkIntegrationUsed устанавливает last_used_at и updated_at в текущее время БД.
// Отсутствие записи не считается ошибкой: количество обновлённых строк не проверяется.
func (r *Repository) MarkIntegrationUsed(ctx context.Context, integrationID uuid.UUID) error {
	const query = `
		UPDATE ticket_integrations
		SET last_used_at = now(),
			updated_at = now()
		WHERE id = $1
	`

	_, err := r.writePool.Exec(ctx, query, integrationID)

	if err != nil {
		return fmt.Errorf("repository: MarkIntegrationUsed(): %w", err)
	}

	return nil
}

// ListIntegrations читает страницу источников от новых к старым без хешей секретов.
// Общее количество берёт из оконного COUNT; для пустой страницы возвращает ноль.
func (r *Repository) ListIntegrations(
	ctx context.Context,
	limit int32,
	offset int32,
) ([]*models.TicketIntegration, int64, error) {
	const query = `
		SELECT
			id, name, client_id, secret_prefix, allowed_department_id,
			is_active, created_by, created_at, updated_at, last_used_at,
			count(*) OVER()
		FROM ticket_integrations
		ORDER BY created_at DESC, id DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.readPool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("repository: ListIntegrations(): %w", err)
	}
	defer rows.Close()

	integrations := make([]*models.TicketIntegration, 0, limit)
	var total int64

	for rows.Next() {
		integration, rowTotal, scanErr := scanTicketIntegrationWithTotal(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf("repository: ListIntegrations(): %w", scanErr)
		}

		total = rowTotal
		integrations = append(integrations, integration)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("repository: ListIntegrations(): %w", err)
	}

	return integrations, total, nil
}

// SetIntegrationActive меняет активность источника и возвращает обновлённые метаданные.
// При отсутствии integrationID возвращает ErrNotFound; секрет не изменяет.
func (r *Repository) SetIntegrationActive(
	ctx context.Context,
	integrationID uuid.UUID,
	isActive bool,
) (*models.TicketIntegration, error) {
	const query = `
		UPDATE ticket_integrations
		SET is_active = $2, updated_at = now()
		WHERE id = $1
		RETURNING id, name, client_id, secret_prefix, allowed_department_id,
			is_active, created_by, created_at, updated_at, last_used_at
	`

	integration, err := scanTicketIntegration(r.writePool.QueryRow(ctx, query, integrationID, isActive))
	if err != nil {
		return nil, fmt.Errorf("repository: SetIntegrationActive(): %w", err)
	}

	return integration, nil
}

// RotateIntegrationSecret заменяет хеш и префикс секрета, сохраняя активность источника.
// Возвращает обновлённые метаданные либо ErrNotFound, если integrationID отсутствует.
func (r *Repository) RotateIntegrationSecret(
	ctx context.Context,
	integrationID uuid.UUID,
	secretHash string,
	secretPrefix string,
) (*models.TicketIntegration, error) {
	const query = `
		UPDATE ticket_integrations
		SET secret_hash = $2, secret_prefix = $3, updated_at = now()
		WHERE id = $1
		RETURNING id, name, client_id, secret_prefix, allowed_department_id,
			is_active, created_by, created_at, updated_at, last_used_at
	`

	integration, err := scanTicketIntegration(
		r.writePool.QueryRow(ctx, query, integrationID, secretHash, secretPrefix),
	)
	if err != nil {
		return nil, fmt.Errorf("repository: RotateIntegrationSecret(): %w", err)
	}

	return integration, nil
}

// scanTicketIntegration считывает метаданные источника с необязательными департаментом
// и временем использования. Преобразует pgx.ErrNoRows в ErrNotFound.
func scanTicketIntegration(s scanner) (*models.TicketIntegration, error) {
	var integration models.TicketIntegration

	var allowedDepartmentID sql.NullString
	var lastUsedAt sql.NullTime

	err := s.Scan(
		&integration.ID,
		&integration.Name,
		&integration.ClientID,
		&integration.SecretPrefix,
		&allowedDepartmentID,
		&integration.IsActive,
		&integration.CreatedBy,
		&integration.CreatedAt,
		&integration.UpdatedAt,
		&lastUsedAt,
	)

	if err != nil {

		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}

		return nil, err
	}

	if allowedDepartmentID.Valid {
		parsed, parseErr := uuid.Parse(allowedDepartmentID.String)

		if parseErr != nil {
			return nil, parseErr
		}

		integration.AllowedDepartmentID = &parsed
	}

	if lastUsedAt.Valid {
		integration.LastUsedAt = &lastUsedAt.Time
	}

	return &integration, nil
}

// scanTicketIntegrationWithTotal считывает метаданные источника и оконный COUNT.
// Ошибки сканирования и разбора UUID возвращает без преобразования.
func scanTicketIntegrationWithTotal(s scanner) (*models.TicketIntegration, int64, error) {
	var integration models.TicketIntegration
	var allowedDepartmentID sql.NullString
	var lastUsedAt sql.NullTime
	var total int64

	err := s.Scan(
		&integration.ID,
		&integration.Name,
		&integration.ClientID,
		&integration.SecretPrefix,
		&allowedDepartmentID,
		&integration.IsActive,
		&integration.CreatedBy,
		&integration.CreatedAt,
		&integration.UpdatedAt,
		&lastUsedAt,
		&total,
	)
	if err != nil {
		return nil, 0, err
	}

	if allowedDepartmentID.Valid {
		parsed, parseErr := uuid.Parse(allowedDepartmentID.String)
		if parseErr != nil {
			return nil, 0, parseErr
		}
		integration.AllowedDepartmentID = &parsed
	}

	if lastUsedAt.Valid {
		integration.LastUsedAt = &lastUsedAt.Time
	}

	return &integration, total, nil
}

// scanIntegrationCredential считывает источник вместе с хешем секрета для проверки доступа.
// Преобразует pgx.ErrNoRows в ErrNotFound и сохраняет NULL-поля как nil.
func scanIntegrationCredential(s scanner) (*integrationCredential, error) {
	var integration models.TicketIntegration
	var secretHash string

	var allowedDepartmentID sql.NullString
	var lastUsedAt sql.NullTime

	err := s.Scan(
		&integration.ID,
		&integration.Name,
		&integration.ClientID,
		&integration.SecretPrefix,
		&allowedDepartmentID,
		&integration.IsActive,
		&integration.CreatedBy,
		&integration.CreatedAt,
		&integration.UpdatedAt,
		&lastUsedAt,
		&secretHash,
	)

	if err != nil {

		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}

		return nil, err
	}

	if allowedDepartmentID.Valid {
		parsed, parseErr := uuid.Parse(allowedDepartmentID.String)

		if parseErr != nil {
			return nil, parseErr
		}

		integration.AllowedDepartmentID = &parsed
	}

	if lastUsedAt.Valid {
		integration.LastUsedAt = &lastUsedAt.Time
	}

	return &integrationCredential{
		Integration: &integration,
		SecretHash:  secretHash,
	}, nil
}
