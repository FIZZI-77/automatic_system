package repository

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"profile/models"
)

func TestMapDatabaseError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
	}{
		{name: "not found", err: pgx.ErrNoRows, target: models.ErrNotFound},
		{name: "unique", err: &pgconn.PgError{Code: "23505"}, target: models.ErrAlreadyExists},
		{name: "foreign key", err: &pgconn.PgError{Code: "23503"}, target: models.ErrNotFound},
		{name: "check", err: &pgconn.PgError{Code: "23514"}, target: models.ErrValidation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := mapDatabaseError("test", tt.err); !errors.Is(err, tt.target) {
				t.Fatalf("expected %v, got %v", tt.target, err)
			}
		})
	}
}

func TestSortHelpersUseAllowlist(t *testing.T) {
	if got := userProfileSortColumn(models.UserProfileSortByFullName); got != "full_name" {
		t.Fatalf("unexpected user profile sort column: %s", got)
	}
	if got := userProfileSortColumn(models.UserProfileSortBy("DROP TABLE")); got != "created_at" {
		t.Fatalf("unsafe user profile sort fallback: %s", got)
	}
	if got := workProfileSortColumn(models.WorkProfileSortByPosition); got != "wp.position" {
		t.Fatalf("unexpected work profile sort column: %s", got)
	}
	if got := workProfileSortColumn(models.WorkProfileSortBy("DROP TABLE")); got != "wp.created_at" {
		t.Fatalf("unsafe work profile sort fallback: %s", got)
	}
	if got := sortOrderSQL(models.SortOrder("DROP TABLE")); got != "DESC" {
		t.Fatalf("unsafe sort order fallback: %s", got)
	}
}

func TestEvaluateCanJoinBrigade(t *testing.T) {
	departmentID := uuid.New()
	otherDepartmentID := uuid.New()
	tests := []struct {
		name       string
		status     models.WorkProfileStatus
		department uuid.UUID
		allowed    bool
		reason     models.CanJoinBrigadeReason
	}{
		{name: "active", status: models.WorkProfileStatusActive, department: departmentID, allowed: true, reason: models.CanJoinBrigadeReasonAllowed},
		{name: "on shift", status: models.WorkProfileStatusOnShift, department: departmentID, allowed: true, reason: models.CanJoinBrigadeReasonAllowed},
		{name: "inactive", status: models.WorkProfileStatusInactive, department: departmentID, reason: models.CanJoinBrigadeReasonProfileInactive},
		{name: "suspended", status: models.WorkProfileStatusSuspended, department: departmentID, reason: models.CanJoinBrigadeReasonProfileSuspended},
		{name: "off shift", status: models.WorkProfileStatusOffShift, department: departmentID, reason: models.CanJoinBrigadeReasonProfileOffShift},
		{name: "department mismatch", status: models.WorkProfileStatusActive, department: otherDepartmentID, reason: models.CanJoinBrigadeReasonDepartmentMismatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := evaluateCanJoinBrigade(tt.status, tt.department, departmentID)
			if allowed != tt.allowed || reason != tt.reason {
				t.Fatalf("expected allowed=%v reason=%s, got allowed=%v reason=%s", tt.allowed, tt.reason, allowed, reason)
			}
		})
	}
}

func TestNewRepositoryInitializesImplementations(t *testing.T) {
	repository := NewRepository(DBPools{})
	if repository.UserProfileRepository == nil {
		t.Fatal("user profile repository is nil")
	}
	if repository.WorkProfileRepository == nil {
		t.Fatal("work profile repository is nil")
	}
}
