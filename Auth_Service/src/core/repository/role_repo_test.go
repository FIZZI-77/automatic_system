package repository

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
)

func TestRoleRepo_AssignRoleToUser_And_GetRolesByUserID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	roleRepo := NewRoleRepoStruct(db)

	userID := createTestUser(t, repo)

	roleID := createTestRole(t, db, "admin")

	err := roleRepo.AssignRoleToUser(ctx, userID, roleID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	roles, err := roleRepo.GetRolesByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(roles))
	}

	if roles[0] != "admin" {
		t.Fatalf("expected role admin, got %s", roles[0])
	}
}

func TestRoleRepo_GetRolesByUserID_MultipleRoles(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	roleRepo := NewRoleRepoStruct(db)

	userID := createTestUser(t, repo)

	adminRoleID := createTestRole(t, db, "admin")
	userRoleID := createTestRole(t, db, "user")

	err := roleRepo.AssignRoleToUser(ctx, userID, adminRoleID)
	if err != nil {
		t.Fatalf("failed to assign admin role: %v", err)
	}

	err = roleRepo.AssignRoleToUser(ctx, userID, userRoleID)
	if err != nil {
		t.Fatalf("failed to assign user role: %v", err)
	}

	roles, err := roleRepo.GetRolesByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}

	roleMap := make(map[string]bool)
	for _, role := range roles {
		roleMap[role] = true
	}

	if !roleMap["admin"] {
		t.Fatal("expected role admin")
	}

	if !roleMap["user"] {
		t.Fatal("expected role user")
	}
}

func TestRoleRepo_GetRolesByUserID_NoRoles(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	roleRepo := NewRoleRepoStruct(db)

	userID := createTestUser(t, repo)

	roles, err := roleRepo.GetRolesByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(roles) != 0 {
		t.Fatalf("expected 0 roles, got %d", len(roles))
	}
}

func TestRoleRepo_GetRolesByUserID_UnknownUser(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	roleRepo := NewRoleRepoStruct(db)

	roles, err := roleRepo.GetRolesByUserID(ctx, uuid.New())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(roles) != 0 {
		t.Fatalf("expected 0 roles, got %d", len(roles))
	}
}

func TestRoleRepo_AssignRoleToUser_DuplicateDoesNothing(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	roleRepo := NewRoleRepoStruct(db)

	userID := createTestUser(t, repo)
	roleID := createTestRole(t, db, "admin")

	err := roleRepo.AssignRoleToUser(ctx, userID, roleID)
	if err != nil {
		t.Fatalf("first assign should be successful, got %v", err)
	}

	err = roleRepo.AssignRoleToUser(ctx, userID, roleID)
	if err != nil {
		t.Fatalf("second assign should not fail because of ON CONFLICT DO NOTHING, got %v", err)
	}

	roles, err := roleRepo.GetRolesByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(roles) != 1 {
		t.Fatalf("expected 1 role after duplicate assign, got %d", len(roles))
	}

	if roles[0] != "admin" {
		t.Fatalf("expected role admin, got %s", roles[0])
	}
}

func TestRoleRepo_AssignRoleToUser_UnknownUser(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	roleRepo := NewRoleRepoStruct(db)

	roleID := createTestRole(t, db, "admin")

	err := roleRepo.AssignRoleToUser(ctx, uuid.New(), roleID)
	if err == nil {
		t.Fatal("expected error because user does not exist")
	}
}

func TestRoleRepo_AssignRoleToUser_UnknownRole(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepo(db)
	roleRepo := NewRoleRepoStruct(db)

	userID := createTestUser(t, repo)

	err := roleRepo.AssignRoleToUser(ctx, userID, uuid.New())
	if err == nil {
		t.Fatal("expected error because role does not exist")
	}
}

func createTestRole(t *testing.T, db *sql.DB, name string) uuid.UUID {
	t.Helper()

	var roleID uuid.UUID

	const query = `
		INSERT INTO roles (name)
		VALUES ($1)
		ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		RETURNING id
	`

	err := db.QueryRowContext(context.Background(), query, name).Scan(&roleID)
	if err != nil {
		t.Fatalf("failed to create test role %s: %v", name, err)
	}

	if roleID == uuid.Nil {
		t.Fatal("expected non-empty role id")
	}

	return roleID
}
