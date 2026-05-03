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

func TestOneTimeTokenRepo_CreateOneTimeToken(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	oneTimeRepo := NewOneTimeTokenRepoStruct(db)

	userID := createTestUser(t, repo)

	token := &models.OneTimeToken{
		UserID:    userID,
		TokenHash: fmt.Sprintf("token-hash-%s", uuid.New().String()),
		Type:      models.TokenTypeEmailVerification,
		ExpiresAt: time.Now().Add(time.Hour),
		UsedAt:    nil,
	}

	err := oneTimeRepo.CreateOneTimeToken(ctx, token)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if token.ID == uuid.Nil {
		t.Fatal("expected token id to be filled")
	}

	if token.CreatedAt.IsZero() {
		t.Fatal("expected created_at to be filled")
	}
}

func TestOneTimeTokenRepo_GetOneTimeTokenByHashAndType_Success(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	oneTimeRepo := NewOneTimeTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	tokenHash := fmt.Sprintf("token-hash-%s", uuid.New().String())

	token := &models.OneTimeToken{
		UserID:    userID,
		TokenHash: tokenHash,
		Type:      models.TokenTypeEmailVerification,
		ExpiresAt: time.Now().Add(time.Hour),
		UsedAt:    nil,
	}

	err := oneTimeRepo.CreateOneTimeToken(ctx, token)
	if err != nil {
		t.Fatalf("failed to create one-time token: %v", err)
	}

	foundToken, err := oneTimeRepo.GetOneTimeTokenByHashAndType(
		ctx,
		tokenHash,
		models.TokenTypeEmailVerification,
	)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if foundToken.ID != token.ID {
		t.Fatalf("expected token id %s, got %s", token.ID, foundToken.ID)
	}

	if foundToken.UserID != userID {
		t.Fatalf("expected user id %s, got %s", userID, foundToken.UserID)
	}

	if foundToken.TokenHash != tokenHash {
		t.Fatalf("expected token hash %s, got %s", tokenHash, foundToken.TokenHash)
	}

	if foundToken.Type != models.TokenTypeEmailVerification {
		t.Fatalf("expected token type %s, got %s", models.TokenTypeEmailVerification, foundToken.Type)
	}

	if foundToken.UsedAt != nil {
		t.Fatal("expected used_at nil")
	}

	if foundToken.CreatedAt.IsZero() {
		t.Fatal("expected created_at not zero")
	}
}

func TestOneTimeTokenRepo_GetOneTimeTokenByHashAndType_NotFound(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	oneTimeRepo := NewOneTimeTokenRepoStruct(db)

	token, err := oneTimeRepo.GetOneTimeTokenByHashAndType(
		ctx,
		"unknown-token-hash",
		models.TokenTypeEmailVerification,
	)

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

func TestOneTimeTokenRepo_GetOneTimeTokenByHashAndType_WrongType(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	oneTimeRepo := NewOneTimeTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	tokenHash := fmt.Sprintf("token-hash-%s", uuid.New().String())

	err := oneTimeRepo.CreateOneTimeToken(ctx, &models.OneTimeToken{
		UserID:    userID,
		TokenHash: tokenHash,
		Type:      models.TokenTypeEmailVerification,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create one-time token: %v", err)
	}

	token, err := oneTimeRepo.GetOneTimeTokenByHashAndType(
		ctx,
		tokenHash,
		models.TokenTypePasswordReset,
	)

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

func TestOneTimeTokenRepo_MarkOneTimeTokenUsed_Success(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	oneTimeRepo := NewOneTimeTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	tokenHash := fmt.Sprintf("token-hash-%s", uuid.New().String())

	token := &models.OneTimeToken{
		UserID:    userID,
		TokenHash: tokenHash,
		Type:      models.TokenTypeEmailVerification,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := oneTimeRepo.CreateOneTimeToken(ctx, token)
	if err != nil {
		t.Fatalf("failed to create one-time token: %v", err)
	}

	err = oneTimeRepo.MarkOneTimeTokenUsed(ctx, token.ID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	updatedToken, err := oneTimeRepo.GetOneTimeTokenByHashAndType(
		ctx,
		tokenHash,
		models.TokenTypeEmailVerification,
	)
	if err != nil {
		t.Fatalf("failed to get updated token: %v", err)
	}

	if updatedToken.UsedAt == nil {
		t.Fatal("expected used_at not nil")
	}
}

func TestOneTimeTokenRepo_MarkOneTimeTokenUsed_AlreadyUsed(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	oneTimeRepo := NewOneTimeTokenRepoStruct(db)

	userID := createTestUser(t, repo)
	tokenHash := fmt.Sprintf("token-hash-%s", uuid.New().String())

	token := &models.OneTimeToken{
		UserID:    userID,
		TokenHash: tokenHash,
		Type:      models.TokenTypeEmailVerification,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := oneTimeRepo.CreateOneTimeToken(ctx, token)
	if err != nil {
		t.Fatalf("failed to create one-time token: %v", err)
	}

	err = oneTimeRepo.MarkOneTimeTokenUsed(ctx, token.ID)
	if err != nil {
		t.Fatalf("first mark should be successful, got %v", err)
	}

	err = oneTimeRepo.MarkOneTimeTokenUsed(ctx, token.ID)
	if err == nil {
		t.Fatal("expected error for already used token")
	}
}

func TestOneTimeTokenRepo_MarkOneTimeTokenUsed_NotFound(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	oneTimeRepo := NewOneTimeTokenRepoStruct(db)

	err := oneTimeRepo.MarkOneTimeTokenUsed(ctx, uuid.New())
	if err == nil {
		t.Fatal("expected error for unknown token")
	}
}

func TestOneTimeTokenRepo_RevokeUnusedTokensByUserIDAndType(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	oneTimeRepo := NewOneTimeTokenRepoStruct(db)

	userID := createTestUser(t, repo)

	firstHash := fmt.Sprintf("first-hash-%s", uuid.New().String())
	secondHash := fmt.Sprintf("second-hash-%s", uuid.New().String())
	passwordResetHash := fmt.Sprintf("password-reset-hash-%s", uuid.New().String())
	expiredHash := fmt.Sprintf("expired-hash-%s", uuid.New().String())

	err := oneTimeRepo.CreateOneTimeToken(ctx, &models.OneTimeToken{
		UserID:    userID,
		TokenHash: firstHash,
		Type:      models.TokenTypeEmailVerification,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create first token: %v", err)
	}

	err = oneTimeRepo.CreateOneTimeToken(ctx, &models.OneTimeToken{
		UserID:    userID,
		TokenHash: secondHash,
		Type:      models.TokenTypeEmailVerification,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create second token: %v", err)
	}

	err = oneTimeRepo.CreateOneTimeToken(ctx, &models.OneTimeToken{
		UserID:    userID,
		TokenHash: passwordResetHash,
		Type:      models.TokenTypePasswordReset,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create password reset token: %v", err)
	}

	err = oneTimeRepo.CreateOneTimeToken(ctx, &models.OneTimeToken{
		UserID:    userID,
		TokenHash: expiredHash,
		Type:      models.TokenTypeEmailVerification,
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create expired token: %v", err)
	}

	err = oneTimeRepo.RevokeUnusedTokensByUserIDAndType(
		ctx,
		userID,
		models.TokenTypeEmailVerification,
	)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	firstToken, err := oneTimeRepo.GetOneTimeTokenByHashAndType(
		ctx,
		firstHash,
		models.TokenTypeEmailVerification,
	)
	if err != nil {
		t.Fatalf("failed to get first token: %v", err)
	}

	secondToken, err := oneTimeRepo.GetOneTimeTokenByHashAndType(
		ctx,
		secondHash,
		models.TokenTypeEmailVerification,
	)
	if err != nil {
		t.Fatalf("failed to get second token: %v", err)
	}

	passwordResetToken, err := oneTimeRepo.GetOneTimeTokenByHashAndType(
		ctx,
		passwordResetHash,
		models.TokenTypePasswordReset,
	)
	if err != nil {
		t.Fatalf("failed to get password reset token: %v", err)
	}

	expiredToken, err := oneTimeRepo.GetOneTimeTokenByHashAndType(
		ctx,
		expiredHash,
		models.TokenTypeEmailVerification,
	)
	if err != nil {
		t.Fatalf("failed to get expired token: %v", err)
	}

	if firstToken.UsedAt == nil {
		t.Fatal("expected first email verification token to be revoked")
	}

	if secondToken.UsedAt == nil {
		t.Fatal("expected second email verification token to be revoked")
	}

	if passwordResetToken.UsedAt != nil {
		t.Fatal("expected password reset token not to be revoked")
	}

	if expiredToken.UsedAt != nil {
		t.Fatal("expected expired token not to be revoked")
	}
}
