package repository

import (
	"auth/models"
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sirupsen/logrus"
)

type RefreshTokenRepoStruct struct {
	writeDB   DBTX
	readDB    DBTX
	writePool *pgxpool.Pool
}

func NewRefreshTokenRepoStruct(writeDB DBTX, readDB ...DBTX) *RefreshTokenRepoStruct {
	reader := writeDB
	if len(readDB) > 0 && readDB[0] != nil {
		reader = readDB[0]
	}
	repo := &RefreshTokenRepoStruct{
		writeDB: writeDB,
		readDB:  reader,
	}
	if pool, ok := writeDB.(*pgxpool.Pool); ok {
		repo.writePool = pool
	}
	return repo
}

func (r *RefreshTokenRepoStruct) beginTx(ctx context.Context, operation string) (pgx.Tx, error) {
	if r.writePool == nil {
		return nil, fmt.Errorf("refresh_token_repo: %s: transaction source is unavailable", operation)
	}

	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("refresh_token_repo: %s: cant begin transaction: %w", operation, err)
	}

	return tx, nil
}

func (r *RefreshTokenRepoStruct) CreateToken(ctx context.Context, token *models.RefreshToken) error {
	var id uuid.UUID

	const query = `INSERT INTO refresh_tokens(user_id, session_id, token_hash, is_revoked, expires_at, used_at, replaced_by_token_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`

	err := r.writeDB.QueryRow(ctx, query,
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

	err := r.readDB.QueryRow(ctx, query, tokenHash).Scan(
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
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("refresh_token_repo: GetByTokenHash(): token not found %w", err)
		}
		return nil, fmt.Errorf("refresh_token_repo: GetByTokenHash(): %w", err)
	}

	return &token, nil

}

func (r *RefreshTokenRepoStruct) RevokeTokenByID(ctx context.Context, tokenID uuid.UUID) error {
	const query = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE id = $1 AND is_revoked = FALSE`
	_, err := r.writeDB.Exec(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("refresh_token_repo: RevokeByID(): cant revoke refresh token: %w", err)
	}
	logrus.Printf("refresh token with id %s revoked", tokenID)
	return nil
}

func (r *RefreshTokenRepoStruct) RevokeTokenBySessionID(ctx context.Context, sessionID uuid.UUID) error {
	const query = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE session_id = $1 AND is_revoked = FALSE`
	_, err := r.writeDB.Exec(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("refresh_token_repo: RevokeBySessionID(): cant revoke refresh token: %w", err)
	}
	logrus.Printf("refresh token with session id %s revoked", sessionID)
	return nil

}

func (r *RefreshTokenRepoStruct) RevokeAllTokenByUserID(ctx context.Context, userID uuid.UUID) error {
	const query = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE user_id = $1 AND is_revoked = FALSE`
	_, err := r.writeDB.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("refresh_token_repo: RevokeAllByUserID(): cant revoke refresh token: %w", err)
	}
	logrus.Printf("refresh token with user id %s revoked", userID)
	return nil

}

func (r *RefreshTokenRepoStruct) MarkUsedAndReplaceToken(ctx context.Context, oldTokenID uuid.UUID, newToken *models.RefreshToken) error {
	var newTokenID uuid.UUID
	tx, err := r.beginTx(ctx, "MarkUsedAndReplace()")
	if err != nil {
		return err
	}
	defer rollbackTxOnCancel(ctx, tx)()

	const insertNewToken = `INSERT INTO refresh_tokens(user_id, session_id, token_hash, is_revoked, expires_at, used_at, replaced_by_token_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`

	err = tx.QueryRow(
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
		return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): failed insert new token, transaction rollback: %w", err)
	}

	logrus.Printf("refresh token with id %s created", newTokenID)

	const updateOldToken = `UPDATE refresh_tokens
	SET is_revoked = true, revoked_at = now(), used_at = now(), replaced_by_token_id = $1
	WHERE id = $2 AND is_revoked = FALSE`

	result, err := tx.Exec(ctx, updateOldToken, newTokenID, oldTokenID)
	if err != nil {
		return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): failed update old token, transaction rollback: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): old token not found or already revoked")
	}
	logrus.Printf("refresh token updated")

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("refresh_token_repo: MarkUsedAndReplace(): cant commit transaction: %w", err)
	}

	return nil
}
