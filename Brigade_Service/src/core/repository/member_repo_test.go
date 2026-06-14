package repository

import (
	"brigade/models"
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestMemberRepository_AddListChangeAvailabilityRemove(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepo(db)
	ctx := context.Background()
	brigade := createTestBrigade(t, repo, uuid.New())
	userID := uuid.New()

	added, err := repo.AddBrigadeMember(ctx, &models.AddBrigadeMemberInput{
		BrigadeID: brigade.ID,
		UserID:    userID,
		Role:      models.BrigadeMemberRoleLead,
	})
	if err != nil {
		t.Fatalf("add member failed: %v", err)
	}
	if added.Member.UserID != userID {
		t.Fatalf("expected user id %s, got %s", userID, added.Member.UserID)
	}

	members, err := repo.ListBrigadeMembers(ctx, &models.ListBrigadeMembersInput{BrigadeID: brigade.ID, Limit: 10})
	if err != nil {
		t.Fatalf("list members failed: %v", err)
	}
	if members.Total != 1 || len(members.Members) != 1 {
		t.Fatalf("expected one member, got total=%d len=%d", members.Total, len(members.Members))
	}

	changed, err := repo.ChangeBrigadeMemberRole(ctx, &models.ChangeBrigadeMemberRoleInput{
		BrigadeID: brigade.ID,
		MemberID:  added.Member.ID,
		Role:      models.BrigadeMemberRoleDriver,
	})
	if err != nil {
		t.Fatalf("change member role failed: %v", err)
	}
	if changed.Member.Role != models.BrigadeMemberRoleDriver {
		t.Fatalf("expected driver role, got %s", changed.Member.Role)
	}

	availability, err := repo.SetBrigadeMemberAvailability(ctx, &models.SetBrigadeMemberAvailabilityInput{
		BrigadeID: brigade.ID,
		MemberID:  added.Member.ID,
		Status:    models.BrigadeMemberAvailabilityUnavailable,
		Reason:    "break",
	})
	if err != nil {
		t.Fatalf("set availability failed: %v", err)
	}
	if availability.Member.AvailabilityStatus != models.BrigadeMemberAvailabilityUnavailable {
		t.Fatalf("expected unavailable, got %s", availability.Member.AvailabilityStatus)
	}

	byUser, err := repo.GetBrigadeByUserID(ctx, &models.GetBrigadeByUserIDInput{UserID: userID, OnlyActive: true})
	if err != nil {
		t.Fatalf("get brigade by user failed: %v", err)
	}
	if byUser.Member.ID != added.Member.ID {
		t.Fatalf("expected member id %s, got %s", added.Member.ID, byUser.Member.ID)
	}

	removed, err := repo.RemoveBrigadeMember(ctx, &models.RemoveBrigadeMemberInput{
		BrigadeID: brigade.ID,
		MemberID:  added.Member.ID,
		Reason:    "left",
	})
	if err != nil {
		t.Fatalf("remove member failed: %v", err)
	}
	if removed.Member.Active {
		t.Fatal("expected removed member inactive")
	}

	history, err := repo.GetBrigadeMemberHistory(ctx, &models.GetBrigadeMemberHistoryInput{BrigadeID: brigade.ID, Limit: 10})
	if err != nil {
		t.Fatalf("get member history failed: %v", err)
	}
	if history.Total != 3 {
		t.Fatalf("expected 3 member history items, got %d", history.Total)
	}

	statusHistory, err := repo.GetBrigadeMemberStatusHistory(ctx, &models.GetBrigadeMemberStatusHistoryInput{BrigadeID: brigade.ID, Limit: 10})
	if err != nil {
		t.Fatalf("get member status history failed: %v", err)
	}
	if statusHistory.Total != 1 {
		t.Fatalf("expected 1 status history item, got %d", statusHistory.Total)
	}
}
