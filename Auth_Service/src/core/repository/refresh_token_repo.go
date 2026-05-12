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

type RefreshTokenStruct struct {
	db *sql.DB
}

func NewRefreshTokenRepo(db *sql.DB) *RefreshTokenStruct {
	return &RefreshTokenStruct{
		db: db,
	}
}

func (r *RefreshTokenStruct) Create(ctx context.Context, token *models.RefreshToken) error {
	var id uuid.UUID

	const query = `INSERT INTO refresh_tokens(user_id, session_id, token_hash, is_revoked, expires_at, used_at, replaced_by_token_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`

	err := r.db.QueryRowContext(ctx, query,
		token.UserID,
		token.SessionID,
		token.TokenHash,
		token.IsRevoked,
		token.ExpiresAt,
		token.CreatedAt,
		token.ReplacedByTokenID,
	).Scan(&id)

	if err != nil {
		return fmt.Errorf("refresh_token_repo: Create(): cant create refresh token %w", err)
	}

	logrus.Printf("refresh token with id %s created", id)
	return nil
}

func (r *RefreshTokenStruct) GetByTokenHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	var token models.RefreshToken

	const query = `SELECT id, user_id, session_id, token_hash, is_revoked, revoked_at, expires_at, used_at, replaced_by_token_id, created_at
	FROM refresh_tokens WHERE token_hash = $1`

	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.SessionID,
		&token.TokenHash,
		&token.IsRevoked,
		&token.RevokedAt,
		&token.ExpiresAt,
		&token.UsedAt,
		&token.ReplacedByTokenID,
		&token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("refresh_token_repo: GetByTokenHash(): token not found %w", err)
		}
		return nil, fmt.Errorf("refresh_token_repo: GetByTokenHash(): %w", err)
	}

	return &token, nil

}

func (r *RefreshTokenStruct) RevokeByID(ctx context.Context, tokenID uuid.UUID) error {

}

func (r *RefreshTokenStruct) RevokeBySessionID(ctx context.Context, sessionID uuid.UUID) error {

}

func (r *RefreshTokenStruct) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {

}

func (r *RefreshTokenStruct) MarkUsedAndReplace(ctx context.Context, oldTokenID string, newToken *models.RefreshToken) error {

}
