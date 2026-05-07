package repository

import (
	"auth/models"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRefreshTokenRepo_CreateToken_And_GetByTokenHash(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	refreshRepo := NewRefreshTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	sessionID := createTestSession(t, repo, userID)

	tokenHash := fmt.Sprintf("refresh-token-hash-%s", uuid.New().String())

	err := refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:            userID,
		SessionID:         sessionID,
		TokenHash:         tokenHash,
		IsRevoked:         false,
		RevokedAt:         nil,
		ExpiresAt:         time.Now().Add(time.Hour),
		UsedAt:            nil,
		ReplacedByTokenID: nil,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	token, err := refreshRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if token.ID == uuid.Nil {
		t.Fatal("expected token id not nil")
	}

	if token.UserID != userID {
		t.Fatalf("expected user id %s, got %s", userID, token.UserID)
	}

	if token.SessionID != sessionID {
		t.Fatalf("expected session id %s, got %s", sessionID, token.SessionID)
	}

	if token.TokenHash != tokenHash {
		t.Fatalf("expected token hash %s, got %s", tokenHash, token.TokenHash)
	}

	if token.IsRevoked {
		t.Fatal("expected token not revoked")
	}

	if token.RevokedAt != nil {
		t.Fatal("expected revoked_at nil")
	}

	if token.UsedAt != nil {
		t.Fatal("expected used_at nil")
	}

	if token.ReplacedByTokenID != nil {
		t.Fatal("expected replaced_by_token_id nil")
	}

	if token.CreatedAt.IsZero() {
		t.Fatal("expected created_at not zero")
	}
}

func TestRefreshTokenRepo_GetByTokenHash_NotFound(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	refreshRepo := NewRefreshTokenRepoStruct(db)

	token, err := refreshRepo.GetByTokenHash(ctx, "unknown-token-hash")

	if token != nil {
		t.Fatal("expected nil token")
	}

	if err == nil {
		t.Fatal("expected error")
	}

	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows inside error, got %v", err)
	}
}

func TestRefreshTokenRepo_GetByTokenHash_DoesNotReturnRevokedToken(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	refreshRepo := NewRefreshTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	sessionID := createTestSession(t, repo, userID)

	tokenHash := fmt.Sprintf("revoked-token-hash-%s", uuid.New().String())

	err := refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: sessionID,
		TokenHash: tokenHash,
		IsRevoked: true,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create revoked token: %v", err)
	}

	token, err := refreshRepo.GetByTokenHash(ctx, tokenHash)

	if token != nil {
		t.Fatal("expected nil token")
	}

	if err == nil {
		t.Fatal("expected error")
	}

	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows inside error, got %v", err)
	}
}

func TestRefreshTokenRepo_RevokeTokenByID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	refreshRepo := NewRefreshTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	sessionID := createTestSession(t, repo, userID)

	tokenHash := fmt.Sprintf("refresh-token-hash-%s", uuid.New().String())

	err := refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: sessionID,
		TokenHash: tokenHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	token, err := refreshRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("failed to get token: %v", err)
	}

	err = refreshRepo.RevokeTokenByID(ctx, token.ID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	revokedToken, err := getRefreshTokenByIDForTest(ctx, db, token.ID)
	if err != nil {
		t.Fatalf("failed to get revoked token by id: %v", err)
	}

	if !revokedToken.IsRevoked {
		t.Fatal("expected token revoked")
	}

	if revokedToken.RevokedAt == nil {
		t.Fatal("expected revoked_at not nil")
	}
}

func TestRefreshTokenRepo_RevokeTokenBySessionID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	refreshRepo := NewRefreshTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	sessionID := createTestSession(t, repo, userID)

	firstHash := fmt.Sprintf("first-refresh-token-hash-%s", uuid.New().String())
	secondHash := fmt.Sprintf("second-refresh-token-hash-%s", uuid.New().String())

	err := refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: sessionID,
		TokenHash: firstHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create first token: %v", err)
	}

	err = refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: sessionID,
		TokenHash: secondHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create second token: %v", err)
	}

	err = refreshRepo.RevokeTokenBySessionID(ctx, sessionID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	firstToken, err := getRefreshTokenByHashForTest(ctx, db, firstHash)
	if err != nil {
		t.Fatalf("failed to get first token: %v", err)
	}

	secondToken, err := getRefreshTokenByHashForTest(ctx, db, secondHash)
	if err != nil {
		t.Fatalf("failed to get second token: %v", err)
	}

	if !firstToken.IsRevoked {
		t.Fatal("expected first token revoked")
	}

	if firstToken.RevokedAt == nil {
		t.Fatal("expected first token revoked_at not nil")
	}

	if !secondToken.IsRevoked {
		t.Fatal("expected second token revoked")
	}

	if secondToken.RevokedAt == nil {
		t.Fatal("expected second token revoked_at not nil")
	}
}

func TestRefreshTokenRepo_RevokeAllTokenByUserID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	refreshRepo := NewRefreshTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	otherUserID := createTestUser(t, repo)

	sessionID := createTestSession(t, repo, userID)
	otherSessionID := createTestSession(t, repo, otherUserID)

	firstHash := fmt.Sprintf("first-refresh-token-hash-%s", uuid.New().String())
	secondHash := fmt.Sprintf("second-refresh-token-hash-%s", uuid.New().String())
	otherHash := fmt.Sprintf("other-refresh-token-hash-%s", uuid.New().String())

	err := refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: sessionID,
		TokenHash: firstHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create first token: %v", err)
	}

	err = refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: sessionID,
		TokenHash: secondHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create second token: %v", err)
	}

	err = refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    otherUserID,
		SessionID: otherSessionID,
		TokenHash: otherHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create other token: %v", err)
	}

	err = refreshRepo.RevokeAllTokenByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	firstToken, err := getRefreshTokenByHashForTest(ctx, db, firstHash)
	if err != nil {
		t.Fatalf("failed to get first token: %v", err)
	}

	secondToken, err := getRefreshTokenByHashForTest(ctx, db, secondHash)
	if err != nil {
		t.Fatalf("failed to get second token: %v", err)
	}

	otherToken, err := getRefreshTokenByHashForTest(ctx, db, otherHash)
	if err != nil {
		t.Fatalf("failed to get other token: %v", err)
	}

	if !firstToken.IsRevoked {
		t.Fatal("expected first token revoked")
	}

	if firstToken.RevokedAt == nil {
		t.Fatal("expected first token revoked_at not nil")
	}

	if !secondToken.IsRevoked {
		t.Fatal("expected second token revoked")
	}

	if secondToken.RevokedAt == nil {
		t.Fatal("expected second token revoked_at not nil")
	}

	if otherToken.IsRevoked {
		t.Fatal("expected other user token not revoked")
	}

	if otherToken.RevokedAt != nil {
		t.Fatal("expected other user token revoked_at nil")
	}
}

func TestRefreshTokenRepo_MarkUsedAndReplaceToken_Success(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	refreshRepo := NewRefreshTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	sessionID := createTestSession(t, repo, userID)

	oldHash := fmt.Sprintf("old-refresh-token-hash-%s", uuid.New().String())
	newHash := fmt.Sprintf("new-refresh-token-hash-%s", uuid.New().String())

	err := refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: sessionID,
		TokenHash: oldHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create old token: %v", err)
	}

	oldToken, err := refreshRepo.GetByTokenHash(ctx, oldHash)
	if err != nil {
		t.Fatalf("failed to get old token: %v", err)
	}

	err = refreshRepo.MarkUsedAndReplaceToken(ctx, oldToken.ID, &models.RefreshToken{
		UserID:            userID,
		SessionID:         sessionID,
		TokenHash:         newHash,
		IsRevoked:         false,
		ExpiresAt:         time.Now().Add(time.Hour),
		UsedAt:            nil,
		ReplacedByTokenID: nil,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	updatedOldToken, err := getRefreshTokenByIDForTest(ctx, db, oldToken.ID)
	if err != nil {
		t.Fatalf("failed to get old token by id: %v", err)
	}

	if !updatedOldToken.IsRevoked {
		t.Fatal("expected old token revoked")
	}

	if updatedOldToken.RevokedAt == nil {
		t.Fatal("expected old token revoked_at not nil")
	}

	if updatedOldToken.UsedAt == nil {
		t.Fatal("expected old token used_at not nil")
	}

	if updatedOldToken.ReplacedByTokenID == nil {
		t.Fatal("expected old token replaced_by_token_id not nil")
	}

	newToken, err := refreshRepo.GetByTokenHash(ctx, newHash)
	if err != nil {
		t.Fatalf("failed to get new token: %v", err)
	}

	if newToken.ID == uuid.Nil {
		t.Fatal("expected new token id not nil")
	}

	if newToken.UserID != userID {
		t.Fatalf("expected new token user id %s, got %s", userID, newToken.UserID)
	}

	if newToken.SessionID != sessionID {
		t.Fatalf("expected new token session id %s, got %s", sessionID, newToken.SessionID)
	}

	if updatedOldToken.ReplacedByTokenID == nil || *updatedOldToken.ReplacedByTokenID != newToken.ID.String() {
		t.Fatalf("expected replaced_by_token_id %s, got %v", newToken.ID.String(), updatedOldToken.ReplacedByTokenID)
	}
}

func TestRefreshTokenRepo_MarkUsedAndReplaceToken_OldTokenNotFound(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	refreshRepo := NewRefreshTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	sessionID := createTestSession(t, repo, userID)

	err := refreshRepo.MarkUsedAndReplaceToken(ctx, uuid.New(), &models.RefreshToken{
		UserID:    userID,
		SessionID: sessionID,
		TokenHash: fmt.Sprintf("new-refresh-token-hash-%s", uuid.New().String()),
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRefreshTokenRepo_MarkUsedAndReplaceToken_OldTokenAlreadyRevoked(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	refreshRepo := NewRefreshTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	sessionID := createTestSession(t, repo, userID)

	oldHash := fmt.Sprintf("old-revoked-refresh-token-hash-%s", uuid.New().String())

	err := refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: sessionID,
		TokenHash: oldHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create old token: %v", err)
	}

	oldToken, err := refreshRepo.GetByTokenHash(ctx, oldHash)
	if err != nil {
		t.Fatalf("failed to get old token: %v", err)
	}

	err = refreshRepo.RevokeTokenByID(ctx, oldToken.ID)
	if err != nil {
		t.Fatalf("failed to revoke old token: %v", err)
	}

	err = refreshRepo.MarkUsedAndReplaceToken(ctx, oldToken.ID, &models.RefreshToken{
		UserID:    userID,
		SessionID: sessionID,
		TokenHash: fmt.Sprintf("new-refresh-token-hash-%s", uuid.New().String()),
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	if err == nil {
		t.Fatal("expected error")
	}
}

func getRefreshTokenByIDForTest(ctx context.Context, db *sql.DB, tokenID uuid.UUID) (*models.RefreshToken, error) {
	var token models.RefreshToken

	const query = `
		SELECT id, user_id, session_id, token_hash, is_revoked, revoked_at, expires_at, used_at, replaced_by_token_id, created_at
		FROM refresh_tokens
		WHERE id = $1
	`

	err := db.QueryRowContext(ctx, query, tokenID).Scan(
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
		return nil, err
	}

	return &token, nil
}

func getRefreshTokenByHashForTest(ctx context.Context, db *sql.DB, tokenHash string) (*models.RefreshToken, error) {
	var token models.RefreshToken

	const query = `
		SELECT id, user_id, session_id, token_hash, is_revoked, revoked_at, expires_at, used_at, replaced_by_token_id, created_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`

	err := db.QueryRowContext(ctx, query, tokenHash).Scan(
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
		return nil, err
	}

	return &token, nil
}
