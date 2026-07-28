package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"profile/models"
)

func TestUserProfileRepository_CreateGetListUpdate(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()
	userID := uuid.New()
	phone := "+79991234567"

	created, err := repo.CreateUserProfile(ctx, &models.CreateUserProfileInput{
		UserID:                 userID,
		FullName:               "Repo User",
		Phone:                  &phone,
		PreferredContactMethod: models.PreferredContactMethodPhone,
	})
	if err != nil {
		t.Fatalf("create user profile failed: %v", err)
	}
	if created.UserProfile.ID == uuid.Nil {
		t.Fatal("expected user profile id")
	}

	foundByID, err := repo.GetUserProfileByID(ctx, &models.GetUserProfileByIDInput{ID: created.UserProfile.ID})
	if err != nil {
		t.Fatalf("get user profile by id failed: %v", err)
	}
	if foundByID.UserProfile.UserID != userID {
		t.Fatalf("expected user id %s, got %s", userID, foundByID.UserProfile.UserID)
	}

	foundByUserID, err := repo.GetUserProfileByUserID(ctx, &models.GetUserProfileByUserIDInput{UserID: userID})
	if err != nil {
		t.Fatalf("get user profile by user id failed: %v", err)
	}
	if foundByUserID.UserProfile.ID != created.UserProfile.ID {
		t.Fatalf("expected profile id %s, got %s", created.UserProfile.ID, foundByUserID.UserProfile.ID)
	}

	query := "Repo"
	list, err := repo.ListUserProfiles(ctx, &models.ListUserProfilesInput{
		Query:     &query,
		Limit:     10,
		Offset:    0,
		SortBy:    models.UserProfileSortByFullName,
		SortOrder: models.SortOrderAsc,
	})
	if err != nil {
		t.Fatalf("list user profiles failed: %v", err)
	}
	if list.Total != 1 || len(list.UserProfiles) != 1 {
		t.Fatalf("expected one user profile, got total=%d len=%d", list.Total, len(list.UserProfiles))
	}

	newName := "Updated Repo User"
	updated, err := repo.UpdateUserProfile(ctx, &models.UpdateUserProfileInput{
		ID:         created.UserProfile.ID,
		FullName:   &newName,
		ClearPhone: true,
	})
	if err != nil {
		t.Fatalf("update user profile failed: %v", err)
	}
	if updated.UserProfile.FullName != newName {
		t.Fatalf("expected updated name %s, got %s", newName, updated.UserProfile.FullName)
	}
	if updated.UserProfile.Phone != nil {
		t.Fatalf("expected phone to be cleared, got %v", updated.UserProfile.Phone)
	}
}

func TestUserProfileRepository_DuplicateUserID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()
	userID := uuid.New()

	_, err := repo.CreateUserProfile(ctx, &models.CreateUserProfileInput{UserID: userID, FullName: "Duplicate User"})
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	_, err = repo.CreateUserProfile(ctx, &models.CreateUserProfileInput{UserID: userID, FullName: "Duplicate User"})
	if !errors.Is(err, models.ErrAlreadyExists) {
		t.Fatalf("expected already exists, got %v", err)
	}
}
