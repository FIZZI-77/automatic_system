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

type RefreshTokenRepoStruct struct {
	db *sql.DB
}

func NewRefreshTokenRepoStruct(db *sql.DB) *RefreshTokenRepoStruct {
	return &RefreshTokenRepoStruct{
		db: db,
	}
}

func (r *RefreshTokenRepoStruct) Create(ctx context.Context, token *models.RefreshToken) error {
	var id uuid.UUID

	const query = `INSERT INTO refresh_tokens(user_id, session_id, token_hash, is_revoked, expires_at, used_at, replaced_by_token_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`

	err := r.db.QueryRowContext(ctx, query,
		token.UserID,
		token.SessionID,
		token.TokenHash,
		token.IsRevoked,
		token.ExpiresAt,
		token.UsedAt,
		token.ReplacedByTokenID,
	).Scan(&id)

	if err != nil {
		return fmt.Errorf("refresh_token_repo: Create(): cant create refresh token %w", err)
	}

	logrus.Printf("refresh token with id %s created", id)
	return nil
}

func (r *RefreshTokenRepoStruct) GetByTokenHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	var token models.RefreshToken

	const query = `SELECT id, user_id, session_id, token_hash, is_revoked, revoked_at, expires_at, used_at, replaced_by_token_id, created_at
	FROM refresh_tokens WHERE token_hash = $1 AND is_revoked = FALSE`

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

func (r *RefreshTokenRepoStruct) RevokeByID(ctx context.Context, tokenID uuid.UUID) error {
	const query = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE id = $1 AND is_revoked = FALSE`
	_, err := r.db.ExecContext(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("refresh_token_repo: RevokeByID(): cant revoke refresh token: %w", err)
	}
	logrus.Printf("refresh token with id %s revoked", tokenID)
	return nil
}

func (r *RefreshTokenRepoStruct) RevokeBySessionID(ctx context.Context, sessionID uuid.UUID) error {
	const query = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE session_id = $1 AND is_revoked = FALSE`
	_, err := r.db.ExecContext(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("refresh_token_repo: RevokeBySessionID(): cant revoke refresh token: %w", err)
	}
	logrus.Printf("refresh token with session id %s revoked", sessionID)
	return nil

}

func (r *RefreshTokenRepoStruct) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	const query = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE user_id = $1 AND is_revoked = FALSE`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("refresh_token_repo: RevokeAllByUserID(): cant revoke refresh token: %w", err)
	}
	logrus.Printf("refresh token with user id %s revoked", userID)
	return nil

}

func (r *RefreshTokenRepoStruct) MarkUsedAndReplace(ctx context.Context, oldTokenID uuid.UUID, newToken *models.RefreshToken) error {
	var newTokenID uuid.UUID
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): cant begin transaction: %w", err)
	}

	const insertNewToken = `INSERT INTO refresh_tokens(user_id, session_id, token_hash, is_revoked, expires_at, used_at, replaced_by_token_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`

	err = tx.QueryRowContext(
		ctx,
		insertNewToken,
		newToken.UserID,
		newToken.SessionID,
		newToken.TokenHash,
		newToken.IsRevoked,
		newToken.ExpiresAt,
		newToken.UsedAt,
		newToken.ReplacedByTokenID,
	).Scan(&newTokenID)

	if err != nil {
		errTx := tx.Rollback()
		if errTx != nil {
			return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): cant rollback transaction: %w", err)
		}
		return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): failed insert new token, transaction rollback: %w", err)
	}

	logrus.Printf("refresh token with id %s created", newTokenID)

	const updateOldToken = `UPDATE refresh_tokens
	SET is_revoked = true, revoked_at = now(), used_at = now(), replaced_by_token_id = $1
	WHERE id = $2 AND is_revoked = FALSE`

	result, err := tx.ExecContext(ctx, updateOldToken, newTokenID, oldTokenID)
	if err != nil {
		errTx := tx.Rollback()
		if errTx != nil {
			return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): cant rollback transaction: %w", errTx)
		}
		return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): failed update old token, transaction rollback: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): rowsAffected failed: %v; rollback failed: %w", err, rollbackErr)
		}
		return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): cant get affected rows: %w", err)
	}

	if rowsAffected == 0 {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): old token not updated; rollback failed: %w", rollbackErr)
		}
		return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): old token not found or already revoked")
	}
	logrus.Printf("refresh token updated")

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): cant commit transaction: %w", err)
	}

	return nil
}
