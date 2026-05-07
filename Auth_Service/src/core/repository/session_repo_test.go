package repository

import (
	"auth/models"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSessionRepo_CreateSession_And_GetSessionByID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	sessionRepo := NewSessionRepoStruct(db)

	userID := createTestUser(t, repo)
	expiresAt := time.Now().Add(time.Hour)

	sessionID, err := sessionRepo.CreateSession(ctx, &models.Session{
		UserID:     userID,
		ClientID:   "web-client",
		IP:         "127.0.0.1",
		UserAgent:  "Mozilla/5.0",
		RevokedAt:  nil,
		ExpiresAt:  expiresAt,
		LastSeenAt: nil,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if sessionID == uuid.Nil {
		t.Fatal("expected non-empty session id")
	}

	session, err := sessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if session.ID != sessionID {
		t.Fatalf("expected session id %s, got %s", sessionID, session.ID)
	}

	if session.UserID != userID {
		t.Fatalf("expected user id %s, got %s", userID, session.UserID)
	}

	if session.ClientID != "web-client" {
		t.Fatalf("expected client_id web-client, got %s", session.ClientID)
	}

	if session.IP != "127.0.0.1" {
		t.Fatalf("expected ip 127.0.0.1, got %s", session.IP)
	}

	if session.UserAgent != "Mozilla/5.0" {
		t.Fatalf("expected user_agent Mozilla/5.0, got %s", session.UserAgent)
	}

	if session.IsRevoked {
		t.Fatal("expected session not revoked")
	}

	if session.RevokedAt != nil {
		t.Fatal("expected revoked_at nil")
	}

	if session.LastSeenAt != nil {
		t.Fatal("expected last_seen_at nil")
	}

	if session.CreatedAt.IsZero() {
		t.Fatal("expected created_at not zero")
	}
}

func TestSessionRepo_GetSessionByID_NotFound(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	sessionRepo := NewSessionRepoStruct(db)

	session, err := sessionRepo.GetSessionByID(ctx, uuid.New())

	if session != nil {
		t.Fatal("expected nil session")
	}

	if err == nil {
		t.Fatal("expected error")
	}

	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows inside error, got %v", err)
	}
}

func TestSessionRepo_GetSessionByUserID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	sessionRepo := NewSessionRepoStruct(db)

	userID := createTestUser(t, repo)
	otherUserID := createTestUser(t, repo)

	firstSessionID, err := sessionRepo.CreateSession(ctx, &models.Session{
		UserID:    userID,
		ClientID:  "web-client-1",
		IP:        "127.0.0.1",
		UserAgent: "Mozilla/5.0",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create first session: %v", err)
	}

	secondSessionID, err := sessionRepo.CreateSession(ctx, &models.Session{
		UserID:    userID,
		ClientID:  "web-client-2",
		IP:        "127.0.0.2",
		UserAgent: "Chrome",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create second session: %v", err)
	}

	_, err = sessionRepo.CreateSession(ctx, &models.Session{
		UserID:    otherUserID,
		ClientID:  "other-client",
		IP:        "127.0.0.3",
		UserAgent: "Safari",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create other user session: %v", err)
	}

	sessions, err := sessionRepo.GetSessionByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	ids := make(map[uuid.UUID]bool)
	for _, session := range sessions {
		ids[session.ID] = true

		if session.UserID != userID {
			t.Fatalf("expected only user id %s, got %s", userID, session.UserID)
		}
	}

	if !ids[firstSessionID] {
		t.Fatalf("expected first session %s in result", firstSessionID)
	}

	if !ids[secondSessionID] {
		t.Fatalf("expected second session %s in result", secondSessionID)
	}
}

func TestSessionRepo_GetSessionByUserID_NoSessions(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	sessionRepo := NewSessionRepoStruct(db)

	userID := createTestUser(t, repo)

	sessions, err := sessionRepo.GetSessionByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestSessionRepo_GetSessionByUserID_UnknownUser(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	sessionRepo := NewSessionRepoStruct(db)

	sessions, err := sessionRepo.GetSessionByUserID(ctx, uuid.New())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestSessionRepo_RevokeSessionByID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	sessionRepo := NewSessionRepoStruct(db)

	userID := createTestUser(t, repo)
	sessionID := createTestSession(t, repo, userID)

	err := sessionRepo.RevokeSessionByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	session, err := sessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}

	if !session.IsRevoked {
		t.Fatal("expected session revoked")
	}

	if session.RevokedAt == nil {
		t.Fatal("expected revoked_at not nil")
	}
}

func TestSessionRepo_RevokeSessionByID_UnknownSession_DoesNotFail(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	sessionRepo := NewSessionRepoStruct(db)

	err := sessionRepo.RevokeSessionByID(ctx, uuid.New())
	if err != nil {
		t.Fatalf("expected nil error for unknown session, got %v", err)
	}
}

func TestSessionRepo_RevokeSessionByID_AlreadyRevoked_DoesNotFail(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	sessionRepo := NewSessionRepoStruct(db)

	userID := createTestUser(t, repo)
	sessionID := createTestSession(t, repo, userID)

	err := sessionRepo.RevokeSessionByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("first revoke should be successful, got %v", err)
	}

	err = sessionRepo.RevokeSessionByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("second revoke should not fail, got %v", err)
	}
}

func TestSessionRepo_RevokeAllSessionByUserID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	sessionRepo := NewSessionRepoStruct(db)

	userID := createTestUser(t, repo)
	otherUserID := createTestUser(t, repo)

	firstSessionID := createTestSession(t, repo, userID)
	secondSessionID := createTestSession(t, repo, userID)
	otherSessionID := createTestSession(t, repo, otherUserID)

	count, err := sessionRepo.RevokeAllSessionByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if count != 2 {
		t.Fatalf("expected revoked count 2, got %d", count)
	}

	firstSession, err := sessionRepo.GetSessionByID(ctx, firstSessionID)
	if err != nil {
		t.Fatalf("failed to get first session: %v", err)
	}

	secondSession, err := sessionRepo.GetSessionByID(ctx, secondSessionID)
	if err != nil {
		t.Fatalf("failed to get second session: %v", err)
	}

	otherSession, err := sessionRepo.GetSessionByID(ctx, otherSessionID)
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
		t.Fatal("expected other user revoked_at nil")
	}
}

func TestSessionRepo_RevokeAllSessionByUserID_NoSessions(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	sessionRepo := NewSessionRepoStruct(db)

	count, err := sessionRepo.RevokeAllSessionByUserID(ctx, uuid.New())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if count != 0 {
		t.Fatalf("expected revoked count 0, got %d", count)
	}
}

func TestSessionRepo_UpdateLastSeenSession(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	sessionRepo := NewSessionRepoStruct(db)

	userID := createTestUser(t, repo)
	sessionID := createTestSession(t, repo, userID)

	beforeUpdate, err := sessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("failed to get session before update: %v", err)
	}

	if beforeUpdate.LastSeenAt != nil {
		t.Fatal("expected last_seen_at nil before update")
	}

	err = sessionRepo.UpdateLastSeenSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	afterUpdate, err := sessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("failed to get session after update: %v", err)
	}

	if afterUpdate.LastSeenAt == nil {
		t.Fatal("expected last_seen_at not nil after update")
	}
}

func TestSessionRepo_UpdateLastSeenSession_RevokedSession_DoesNotUpdate(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	sessionRepo := NewSessionRepoStruct(db)

	userID := createTestUser(t, repo)
	sessionID := createTestSession(t, repo, userID)

	err := sessionRepo.RevokeSessionByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("failed to revoke session: %v", err)
	}

	err = sessionRepo.UpdateLastSeenSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	session, err := sessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}

	if session.LastSeenAt != nil {
		t.Fatal("expected last_seen_at nil because revoked session should not be updated")
	}
}

func TestSessionRepo_UpdateLastSeenSession_UnknownSession_DoesNotFail(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	sessionRepo := NewSessionRepoStruct(db)

	err := sessionRepo.UpdateLastSeenSession(ctx, uuid.New())
	if err != nil {
		t.Fatalf("expected nil error for unknown session, got %v", err)
	}
}
