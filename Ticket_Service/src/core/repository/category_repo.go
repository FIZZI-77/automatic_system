package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"ticket/models"
)

type CategoryRepoStruct struct {
	db *sql.DB
}

func NewCategoryRepository(db *sql.DB) *CategoryRepoStruct {
	return &CategoryRepoStruct{
		db: db,
	}
}

type categoryEventPayload struct {
	EventID    uuid.UUID `json:"event_id"`
	EventType  string    `json:"event_type"`
	CategoryID uuid.UUID `json:"category_id"`
	Code       string    `json:"code"`
	Name       string    `json:"name"`
	IsActive   bool      `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (c *CategoryRepoStruct) CreateCategory(ctx context.Context, in *models.CreateCategoryInput) (*models.TicketCategory, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repository: CreateCategory(): begin tx: %w", err)
	}
	defer func(tx *sql.Tx) {
		err := tx.Rollback()
		if err != nil {

		}
	}(tx)

	categoryID := uuid.NewString()

	const query = `
		INSERT INTO ticket_categories (
			id,
			code,
			name,
			description,
			is_active,
			created_at,
			updated_at
		)
		VALUES ($1, $2, $3, $4, true, now(), now())
		RETURNING
			id,
			code,
			name,
			description,
			is_active,
			created_at,
			updated_at
	`

	row := tx.QueryRowContext(
		ctx,
		query,
		categoryID,
		in.Code,
		in.Name,
		in.Description,
	)

	category, err := scanCategory(row)
	if err != nil {
		return nil, fmt.Errorf("repository: CreateCategory(): insert category: %w", err)
	}

	if err = c.insertCategoryOutboxEvent(ctx, tx, "ticket_category.created", category); err != nil {
		return nil, fmt.Errorf("repository: CreateCategory(): insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repository: CreateCategory(): commit: %w", err)
	}

	return category, nil
}

func (c *CategoryRepoStruct) GetCategoryByID(ctx context.Context, categoryID uuid.UUID) (*models.TicketCategory, error) {
	const query = `
		SELECT
			id,
			code,
			name,
			description,
			is_active,
			created_at,
			updated_at
		FROM ticket_categories
		WHERE id = $1
	`

	row := c.db.QueryRowContext(ctx, query, categoryID)

	category, err := scanCategory(row)
	if err != nil {
		return nil, fmt.Errorf("repository: GetCategoryByID(): %w", err)
	}

	return category, nil
}

func (c *CategoryRepoStruct) ListCategories(ctx context.Context, in *models.ListCategoriesInput) ([]*models.TicketCategory, int64, error) {
	whereSQL := ""
	args := make([]any, 0)

	if in.OnlyActive {
		args = append(args, true)
		whereSQL = "WHERE is_active = $1"
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM ticket_categories
		%s
	`, whereSQL)

	var total int64
	if err := c.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("repository: ListCategories(): count: %w", err)
	}

	args = append(args, in.Limit, in.Offset)
	limitArg := len(args) - 1
	offsetArg := len(args)

	listQuery := fmt.Sprintf(`
		SELECT
			id,
			code,
			name,
			description,
			is_active,
			created_at,
			updated_at
		FROM ticket_categories
		%s
		ORDER BY name ASC
		LIMIT $%d OFFSET $%d
	`, whereSQL, limitArg, offsetArg)

	rows, err := c.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("repository: ListCategories(): query: %w", err)
	}
	defer rows.Close()

	categories := make([]*models.TicketCategory, 0)

	for rows.Next() {
		category, err := scanCategory(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("repository: ListCategories(): scan: %w", err)
		}

		categories = append(categories, category)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("repository: ListCategories(): rows: %w", err)
	}

	return categories, total, nil
}

func (c *CategoryRepoStruct) UpdateCategory(ctx context.Context, in *models.UpdateCategoryInput) (*models.TicketCategory, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repository: UpdateCategory(): begin tx: %w", err)
	}
	defer func(tx *sql.Tx) {
		err = tx.Rollback()
		if err != nil {

		}
	}(tx)

	const query = `
		UPDATE ticket_categories
		SET
			name = COALESCE(NULLIF($1, ''), name),
			description = COALESCE(NULLIF($2, ''), description),
			is_active = $3,
			updated_at = now()
		WHERE id = $4
		RETURNING
			id,
			code,
			name,
			description,
			is_active,
			created_at,
			updated_at
	`

	row := tx.QueryRowContext(
		ctx,
		query,
		in.Name,
		in.Description,
		in.IsActive,
		in.CategoryID,
	)

	category, err := scanCategory(row)
	if err != nil {
		return nil, fmt.Errorf("repository: UpdateCategory(): update category: %w", err)
	}

	if err = c.insertCategoryOutboxEvent(ctx, tx, "ticket_category.updated", category); err != nil {
		return nil, fmt.Errorf("repository: UpdateCategory(): insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repository: UpdateCategory(): commit: %w", err)
	}

	return category, nil
}

func (c *CategoryRepoStruct) DeleteCategory(ctx context.Context, in *models.DeleteCategoryInput) (*models.TicketCategory, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repository: DeleteCategory(): begin tx: %w", err)
	}
	defer func(tx *sql.Tx) {
		err := tx.Rollback()
		if err != nil {

		}
	}(tx)

	const query = `
		UPDATE ticket_categories
		SET
			is_active = false,
			updated_at = now()
		WHERE id = $1
		RETURNING
			id,
			code,
			name,
			description,
			is_active,
			created_at,
			updated_at
	`

	row := tx.QueryRowContext(ctx, query, in.CategoryID)

	category, err := scanCategory(row)
	if err != nil {
		return nil, fmt.Errorf("repository: DeleteCategory(): deactivate category: %w", err)
	}

	if err = c.insertCategoryOutboxEvent(ctx, tx, "ticket_category.deactivated", category); err != nil {
		return nil, fmt.Errorf("repository: DeleteCategory(): insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repository: DeleteCategory(): commit: %w", err)
	}

	return category, nil
}

func scanCategory(s scanner) (*models.TicketCategory, error) {
	var category models.TicketCategory

	err := s.Scan(
		&category.ID,
		&category.Code,
		&category.Name,
		&category.Description,
		&category.IsActive,
		&category.CreatedAt,
		&category.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}

		return nil, err
	}

	return &category, nil
}

func (c *CategoryRepoStruct) insertCategoryOutboxEvent(ctx context.Context,
	tx *sql.Tx,
	eventType string,
	category *models.TicketCategory,
) error {
	eventID := uuid.New()

	payload := categoryEventPayload{
		EventID:    eventID,
		EventType:  eventType,
		CategoryID: category.ID,
		Code:       category.Code,
		Name:       category.Name,
		IsActive:   category.IsActive,
		CreatedAt:  category.CreatedAt,
		UpdatedAt:  category.UpdatedAt,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	const query = `
		INSERT INTO outbox_events (
			id,
			aggregate_type,
			aggregate_id,
			event_type,
			payload,
			status,
			attempts,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5::jsonb, 'PENDING', 0, now())
	`

	_, err = tx.ExecContext(
		ctx,
		query,
		eventID,
		"ticket_category",
		category.ID,
		eventType,
		string(payloadBytes),
	)

	return err
}
