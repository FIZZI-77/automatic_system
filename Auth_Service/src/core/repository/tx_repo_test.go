package repository

import (
	"auth/models"
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTXRepo_Logout_RevokesSessionAndTokens(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	txRepo := NewTXRepoStruct(db)
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
		t.Fatalf("failed to create refresh token: %v", err)
	}

	err = txRepo.Logout(ctx, sessionID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	session, err := repo.GetSessionByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}

	if !session.IsRevoked {
		t.Fatal("expected session revoked")
	}

	if session.RevokedAt == nil {
		t.Fatal("expected session revoked_at not nil")
	}

	token, err := getRefreshTokenByHashForTXTest(ctx, db, tokenHash)
	if err != nil {
		t.Fatalf("failed to get refresh token: %v", err)
	}

	if !token.IsRevoked {
		t.Fatal("expected refresh token revoked")
	}

	if token.RevokedAt == nil {
		t.Fatal("expected refresh token revoked_at not nil")
	}
}

func TestTXRepo_Logout_UnknownSession_DoesNotFail(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	txRepo := NewTXRepoStruct(db)

	err := txRepo.Logout(ctx, uuid.New())
	if err != nil {
		t.Fatalf("expected nil error for unknown session, got %v", err)
	}
}

func TestTXRepo_LogoutAll_RevokesUserSessionsAndTokens(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	txRepo := NewTXRepoStruct(db)
	refreshRepo := NewRefreshTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	otherUserID := createTestUser(t, repo)

	firstSessionID := createTestSession(t, repo, userID)
	secondSessionID := createTestSession(t, repo, userID)
	otherSessionID := createTestSession(t, repo, otherUserID)

	firstTokenHash := fmt.Sprintf("first-token-hash-%s", uuid.New().String())
	secondTokenHash := fmt.Sprintf("second-token-hash-%s", uuid.New().String())
	otherTokenHash := fmt.Sprintf("other-token-hash-%s", uuid.New().String())

	err := refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: firstSessionID,
		TokenHash: firstTokenHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create first refresh token: %v", err)
	}

	err = refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: secondSessionID,
		TokenHash: secondTokenHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create second refresh token: %v", err)
	}

	err = refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    otherUserID,
		SessionID: otherSessionID,
		TokenHash: otherTokenHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create other refresh token: %v", err)
	}

	count, err := txRepo.LogoutAll(ctx, userID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if count != 2 {
		t.Fatalf("expected revoked sessions count 2, got %d", count)
	}

	firstSession, err := repo.GetSessionByID(ctx, firstSessionID)
	if err != nil {
		t.Fatalf("failed to get first session: %v", err)
	}

	secondSession, err := repo.GetSessionByID(ctx, secondSessionID)
	if err != nil {
		t.Fatalf("failed to get second session: %v", err)
	}

	otherSession, err := repo.GetSessionByID(ctx, otherSessionID)
	if err != nil {
		t.Fatalf("failed to get other session: %v", err)
	}

	if !firstSession.IsRevoked {
		t.Fatal("expected first session revoked")
	}

	if firstSession.RevokedAt == nil {
		t.Fatal("expected first session revoked_at not nil")
	}

	if !secondSession.IsRevoked {
		t.Fatal("expected second session revoked")
	}

	if secondSession.RevokedAt == nil {
		t.Fatal("expected second session revoked_at not nil")
	}

	if otherSession.IsRevoked {
		t.Fatal("expected other user session not revoked")
	}

	if otherSession.RevokedAt != nil {
		t.Fatal("expected other user session revoked_at nil")
	}

	firstToken, err := getRefreshTokenByHashForTXTest(ctx, db, firstTokenHash)
	if err != nil {
		t.Fatalf("failed to get first token: %v", err)
	}

	secondToken, err := getRefreshTokenByHashForTXTest(ctx, db, secondTokenHash)
	if err != nil {
		t.Fatalf("failed to get second token: %v", err)
	}

	otherToken, err := getRefreshTokenByHashForTXTest(ctx, db, otherTokenHash)
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

func TestTXRepo_LogoutAll_NoSessions(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	txRepo := NewTXRepoStruct(db)

	count, err := txRepo.LogoutAll(ctx, uuid.New())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if count != 0 {
		t.Fatalf("expected revoked sessions count 0, got %d", count)
	}
}

func TestTXRepo_ChangePassword_RevokeOnlyCurrentSession(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	txRepo := NewTXRepoStruct(db)
	refreshRepo := NewRefreshTokenRepoStruct(db)

	userID := createTestUser(t, repo)

	currentSessionID := createTestSession(t, repo, userID)
	otherSessionID := createTestSession(t, repo, userID)

	currentTokenHash := fmt.Sprintf("current-token-hash-%s", uuid.New().String())
	otherTokenHash := fmt.Sprintf("other-token-hash-%s", uuid.New().String())

	err := refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: currentSessionID,
		TokenHash: currentTokenHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create current refresh token: %v", err)
	}

	err = refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: otherSessionID,
		TokenHash: otherTokenHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create other refresh token: %v", err)
	}

	newPasswordHash := "new-password-hash"

	count, err := txRepo.ChangePassword(ctx, userID, newPasswordHash, currentSessionID, false)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if count != 1 {
		t.Fatalf("expected revoked sessions count 1, got %d", count)
	}

	user, err := repo.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}

	if user.PasswordHash != newPasswordHash {
		t.Fatalf("expected password hash %s, got %s", newPasswordHash, user.PasswordHash)
	}

	currentSession, err := repo.GetSessionByID(ctx, currentSessionID)
	if err != nil {
		t.Fatalf("failed to get current session: %v", err)
	}

	otherSession, err := repo.GetSessionByID(ctx, otherSessionID)
	if err != nil {
		t.Fatalf("failed to get other session: %v", err)
	}

	if !currentSession.IsRevoked {
		t.Fatal("expected current session revoked")
	}

	if currentSession.RevokedAt == nil {
		t.Fatal("expected current session revoked_at not nil")
	}

	if otherSession.IsRevoked {
		t.Fatal("expected other session not revoked")
	}

	if otherSession.RevokedAt != nil {
		t.Fatal("expected other session revoked_at nil")
	}

	currentToken, err := getRefreshTokenByHashForTXTest(ctx, db, currentTokenHash)
	if err != nil {
		t.Fatalf("failed to get current token: %v", err)
	}

	otherToken, err := getRefreshTokenByHashForTXTest(ctx, db, otherTokenHash)
	if err != nil {
		t.Fatalf("failed to get other token: %v", err)
	}

	if !currentToken.IsRevoked {
		t.Fatal("expected current token revoked")
	}

	if currentToken.RevokedAt == nil {
		t.Fatal("expected current token revoked_at not nil")
	}

	if otherToken.IsRevoked {
		t.Fatal("expected other token not revoked")
	}

	if otherToken.RevokedAt != nil {
		t.Fatal("expected other token revoked_at nil")
	}
}

func TestTXRepo_ChangePassword_RevokeAllUserSessions(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	txRepo := NewTXRepoStruct(db)
	refreshRepo := NewRefreshTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	otherUserID := createTestUser(t, repo)

	firstSessionID := createTestSession(t, repo, userID)
	secondSessionID := createTestSession(t, repo, userID)
	otherSessionID := createTestSession(t, repo, otherUserID)

	firstTokenHash := fmt.Sprintf("first-token-hash-%s", uuid.New().String())
	secondTokenHash := fmt.Sprintf("second-token-hash-%s", uuid.New().String())
	otherTokenHash := fmt.Sprintf("other-token-hash-%s", uuid.New().String())

	err := refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: firstSessionID,
		TokenHash: firstTokenHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create first refresh token: %v", err)
	}

	err = refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: secondSessionID,
		TokenHash: secondTokenHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create second refresh token: %v", err)
	}

	err = refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    otherUserID,
		SessionID: otherSessionID,
		TokenHash: otherTokenHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create other refresh token: %v", err)
	}

	newPasswordHash := "new-password-hash-all"

	count, err := txRepo.ChangePassword(ctx, userID, newPasswordHash, firstSessionID, true)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if count != 2 {
		t.Fatalf("expected revoked sessions count 2, got %d", count)
	}

	user, err := repo.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}

	if user.PasswordHash != newPasswordHash {
		t.Fatalf("expected password hash %s, got %s", newPasswordHash, user.PasswordHash)
	}

	firstSession, err := repo.GetSessionByID(ctx, firstSessionID)
	if err != nil {
		t.Fatalf("failed to get first session: %v", err)
	}

	secondSession, err := repo.GetSessionByID(ctx, secondSessionID)
	if err != nil {
		t.Fatalf("failed to get second session: %v", err)
	}

	otherSession, err := repo.GetSessionByID(ctx, otherSessionID)
	if err != nil {
		t.Fatalf("failed to get other session: %v", err)
	}

	if !firstSession.IsRevoked {
		t.Fatal("expected first session revoked")
	}

	if firstSession.RevokedAt == nil {
		t.Fatal("expected first session revoked_at not nil")
	}

	if !secondSession.IsRevoked {
		t.Fatal("expected second session revoked")
	}

	if secondSession.RevokedAt == nil {
		t.Fatal("expected second session revoked_at not nil")
	}

	if otherSession.IsRevoked {
		t.Fatal("expected other user session not revoked")
	}

	if otherSession.RevokedAt != nil {
		t.Fatal("expected other user session revoked_at nil")
	}

	firstToken, err := getRefreshTokenByHashForTXTest(ctx, db, firstTokenHash)
	if err != nil {
		t.Fatalf("failed to get first token: %v", err)
	}

	secondToken, err := getRefreshTokenByHashForTXTest(ctx, db, secondTokenHash)
	if err != nil {
		t.Fatalf("failed to get second token: %v", err)
	}

	otherToken, err := getRefreshTokenByHashForTXTest(ctx, db, otherTokenHash)
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

func TestTXRepo_ChangePassword_UnknownUser_DoesNotFailBecauseRowsAffectedNotChecked(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	txRepo := NewTXRepoStruct(db)

	count, err := txRepo.ChangePassword(ctx, uuid.New(), "new-password-hash", uuid.New(), true)
	if err != nil {
		t.Fatalf("expected nil error because ChangePassword does not check updated user rows, got %v", err)
	}

	if count != 0 {
		t.Fatalf("expected revoked sessions count 0, got %d", count)
	}
}

func TestTXRepo_ResetPassword_UpdatesPasswordAndRevokesSessionsAndTokens(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	txRepo := NewTXRepoStruct(db)
	refreshRepo := NewRefreshTokenRepoStruct(db)

	userID := createTestUser(t, repo)

	firstSessionID := createTestSession(t, repo, userID)
	secondSessionID := createTestSession(t, repo, userID)

	firstTokenHash := fmt.Sprintf("first-token-hash-%s", uuid.New().String())
	secondTokenHash := fmt.Sprintf("second-token-hash-%s", uuid.New().String())

	err := refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: firstSessionID,
		TokenHash: firstTokenHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create first refresh token: %v", err)
	}

	err = refreshRepo.CreateToken(ctx, &models.RefreshToken{
		UserID:    userID,
		SessionID: secondSessionID,
		TokenHash: secondTokenHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create second refresh token: %v", err)
	}

	newPasswordHash := "reset-password-hash"

	count, err := txRepo.ResetPassword(ctx, userID, newPasswordHash)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if count != 2 {
		t.Fatalf("expected revoked sessions count 2, got %d", count)
	}

	user, err := repo.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}

	if user.PasswordHash != newPasswordHash {
		t.Fatalf("expected password hash %s, got %s", newPasswordHash, user.PasswordHash)
	}

	firstSession, err := repo.GetSessionByID(ctx, firstSessionID)
	if err != nil {
		t.Fatalf("failed to get first session: %v", err)
	}

	secondSession, err := repo.GetSessionByID(ctx, secondSessionID)
	if err != nil {
		t.Fatalf("failed to get second session: %v", err)
	}

	if !firstSession.IsRevoked {
		t.Fatal("expected first session revoked")
	}

	if firstSession.RevokedAt == nil {
		t.Fatal("expected first session revoked_at not nil")
	}

	if !secondSession.IsRevoked {
		t.Fatal("expected second session revoked")
	}

	if secondSession.RevokedAt == nil {
		t.Fatal("expected second session revoked_at not nil")
	}

	firstToken, err := getRefreshTokenByHashForTXTest(ctx, db, firstTokenHash)
	if err != nil {
		t.Fatalf("failed to get first token: %v", err)
	}

	secondToken, err := getRefreshTokenByHashForTXTest(ctx, db, secondTokenHash)
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

func TestTXRepo_ResetPassword_UnknownUser_ReturnsError(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	txRepo := NewTXRepoStruct(db)

	count, err := txRepo.ResetPassword(ctx, uuid.New(), "reset-password-hash")

	if err == nil {
		t.Fatal("expected error")
	}

	if count != 0 {
		t.Fatalf("expected count 0, got %d", count)
	}
}

func getRefreshTokenByHashForTXTest(ctx context.Context, db *sql.DB, tokenHash string) (*models.RefreshToken, error) {
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
