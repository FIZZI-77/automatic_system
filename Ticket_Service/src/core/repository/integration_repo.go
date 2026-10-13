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
