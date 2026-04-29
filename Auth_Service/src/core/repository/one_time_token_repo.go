package repository

import (
	"auth/models"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type OneTimeTokenRepoStruct struct {
	db *sql.DB
}

func NewOneTimeTokenRepoStruct(db *sql.DB) *OneTimeTokenRepoStruct {
	return &OneTimeTokenRepoStruct{db: db}
}

func (r *OneTimeTokenRepoStruct) CreateOneTimeToken(ctx context.Context, token *models.OneTimeToken) error {
	const query = `
		INSERT INTO one_time_tokens (
			user_id, token_hash, type, expires_at, used_at
		) VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at
	`

	err := r.db.QueryRowContext(
		ctx,
		query,
		token.UserID,
		token.TokenHash,
		token.Type,
		token.ExpiresAt,
		token.UsedAt,
	).Scan(&token.ID, &token.CreatedAt)
	if err != nil {
		return fmt.Errorf("one_time_token_repo: CreateOneTimeToken(): %w", err)
	}

	logrus.Printf("one-time token created: id=%s type=%s user_id=%s", token.ID, token.Type, token.UserID)
	return nil
}

func (r *OneTimeTokenRepoStruct) GetOneTimeTokenByHashAndType(
	ctx context.Context,
	tokenHash string,
	tokenType models.TokenType,
) (*models.OneTimeToken, error) {
	var token models.OneTimeToken

	const query = `
		SELECT id, user_id, token_hash, type, expires_at, used_at, created_at
		FROM one_time_tokens
		WHERE token_hash = $1 AND type = $2
	`

	err := r.db.QueryRowContext(ctx, query, tokenHash, tokenType).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.Type,
		&token.ExpiresAt,
		&token.UsedAt,
		&token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("one_time_token_repo: GetOneTimeTokenByHashAndType(): token not found: %w", err)
		}
		return nil, fmt.Errorf("one_time_token_repo: GetOneTimeTokenByHashAndType(): %w", err)
	}

	return &token, nil
}

func (r *OneTimeTokenRepoStruct) MarkOneTimeTokenUsed(ctx context.Context, tokenID uuid.UUID) error {
	const query = `
		UPDATE one_time_tokens
		SET used_at = NOW()
		WHERE id = $1 AND used_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("one_time_token_repo: MarkOneTimeTokenUsed(): %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("one_time_token_repo: MarkOneTimeTokenUsed(): rowsAffected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("one_time_token_repo: MarkOneTimeTokenUsed(): token not found or already used")
	}

	return nil
}

func (r *OneTimeTokenRepoStruct) RevokeUnusedTokensByUserIDAndType(
	ctx context.Context,
	userID uuid.UUID,
	tokenType models.TokenType,
) error {
	const query = `
		UPDATE one_time_tokens
		SET used_at = NOW()
		WHERE user_id = $1
		  AND type = $2
		  AND used_at IS NULL
		  AND expires_at > NOW()
	`

	_, err := r.db.ExecContext(ctx, query, userID, tokenType)
	if err != nil {
		return fmt.Errorf("one_time_token_repo: RevokeUnusedTokensByUserIDAndType(): %w", err)
	}

	return nil
}
