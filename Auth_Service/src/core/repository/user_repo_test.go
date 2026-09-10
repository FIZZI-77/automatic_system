package repository

import (
	"auth/models"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestUserRepo_CreateUser_And_GetUserByID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	userRepo := NewUserRepoStruct(db)

	user := &models.User{
		Email:         fmt.Sprintf("user-%s@example.com", uuid.New().String()),
		Username:      "testuser",
		PasswordHash:  "password-hash",
		IsActive:      true,
		EmailVerified: false,
	}

	userID, err := userRepo.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if userID == uuid.Nil {
		t.Fatal("expected non-empty user id")
	}

	foundUser, err := userRepo.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if foundUser.ID != userID {
		t.Fatalf("expected user id %s, got %s", userID, foundUser.ID)
	}

	if foundUser.Email != user.Email {
		t.Fatalf("expected email %s, got %s", user.Email, foundUser.Email)
	}

	if foundUser.Username != user.Username {
		t.Fatalf("expected username %s, got %s", user.Username, foundUser.Username)
	}

	if foundUser.PasswordHash != user.PasswordHash {
		t.Fatalf("expected password hash %s, got %s", user.PasswordHash, foundUser.PasswordHash)
	}

	if !foundUser.IsActive {
		t.Fatal("expected user active")
	}

	if foundUser.EmailVerified {
		t.Fatal("expected email_verified false")
	}

	if foundUser.CreatedAt.IsZero() {
		t.Fatal("expected created_at not zero")
	}
}

func TestUserRepo_CreateUser_And_GetUserByEmail(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	userRepo := NewUserRepoStruct(db)

	email := fmt.Sprintf("email-%s@example.com", uuid.New().String())

	user := &models.User{
		Email:         email,
		Username:      "emailuser",
		PasswordHash:  "password-hash",
		IsActive:      true,
		EmailVerified: true,
	}

	userID, err := userRepo.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	foundUser, err := userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if foundUser.ID != userID {
		t.Fatalf("expected user id %s, got %s", userID, foundUser.ID)
	}

	if foundUser.Email != email {
		t.Fatalf("expected email %s, got %s", email, foundUser.Email)
	}

	if foundUser.Username != "emailuser" {
		t.Fatalf("expected username emailuser, got %s", foundUser.Username)
	}

	if !foundUser.EmailVerified {
		t.Fatal("expected email_verified true")
	}
}

func TestUserRepo_CreateUser_DuplicateEmail_ReturnsError(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	userRepo := NewUserRepoStruct(db)

	email := fmt.Sprintf("duplicate-%s@example.com", uuid.New().String())

	firstUser := &models.User{
		Email:         email,
		Username:      "firstuser",
		PasswordHash:  "password-hash",
		IsActive:      true,
		EmailVerified: false,
	}

	secondUser := &models.User{
		Email:         email,
		Username:      "seconduser",
		PasswordHash:  "password-hash",
		IsActive:      true,
		EmailVerified: false,
	}

	_, err := userRepo.CreateUser(ctx, firstUser)
	if err != nil {
		t.Fatalf("first create should be successful, got %v", err)
	}

	_, err = userRepo.CreateUser(ctx, secondUser)
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}
}

func TestUserRepo_GetUserByID_NotFound(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	userRepo := NewUserRepoStruct(db)

	user, err := userRepo.GetUserByID(ctx, uuid.New())

	if user != nil {
		t.Fatal("expected nil user")
	}

	if err == nil {
		t.Fatal("expected error")
	}

	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows inside error, got %v", err)
	}
}

func TestUserRepo_GetUserByEmail_NotFound(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	userRepo := NewUserRepoStruct(db)

	user, err := userRepo.GetUserByEmail(ctx, "unknown@example.com")

	if user != nil {
		t.Fatal("expected nil user")
	}

	if err == nil {
		t.Fatal("expected error")
	}

	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows inside error, got %v", err)
	}
}

func TestUserRepo_UpdateUser(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	userRepo := NewUserRepoStruct(db)

	userID, err := userRepo.CreateUser(ctx, &models.User{
		Email:         fmt.Sprintf("update-%s@example.com", uuid.New().String()),
		Username:      "oldname",
		PasswordHash:  "old-password-hash",
		IsActive:      true,
		EmailVerified: false,
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	user, err := userRepo.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}

	newEmail := fmt.Sprintf("updated-%s@example.com", uuid.New().String())

	user.Email = newEmail
	user.Username = "newname"
	user.PasswordHash = "new-password-hash"
	user.IsActive = false
	user.EmailVerified = true

	err = userRepo.UpdateUser(ctx, user)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	updatedUser, err := userRepo.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}

	if updatedUser.Email != newEmail {
		t.Fatalf("expected email %s, got %s", newEmail, updatedUser.Email)
	}

	if updatedUser.Username != "newname" {
		t.Fatalf("expected username newname, got %s", updatedUser.Username)
	}

	if updatedUser.PasswordHash != "new-password-hash" {
		t.Fatalf("expected password hash new-password-hash, got %s", updatedUser.PasswordHash)
	}

	if updatedUser.IsActive {
		t.Fatal("expected is_active false")
	}

	if !updatedUser.EmailVerified {
		t.Fatal("expected email_verified true")
	}
}

func TestUserRepo_UpdateUser_UnknownUser_DoesNotFail(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	userRepo := NewUserRepoStruct(db)

	err := userRepo.UpdateUser(ctx, &models.User{
		ID:            uuid.New(),
		Email:         fmt.Sprintf("unknown-%s@example.com", uuid.New().String()),
		Username:      "unknown",
		PasswordHash:  "password-hash",
		IsActive:      true,
		EmailVerified: false,
	})

	if err != nil {
		t.Fatalf("expected nil error because UpdateUser does not check RowsAffected, got %v", err)
	}
}
