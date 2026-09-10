package repository

import (
	"brigade/models"
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMemberRepository_AddListChangeAvailabilityRemove(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
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

	assertMemberEvent(t, db, brigade, added.Member.ID, "BrigadeMemberAdded", map[string]any{
		"role":                string(models.BrigadeMemberRoleLead),
		"active":              true,
		"member_status":       "ACTIVE",
		"availability_status": string(models.BrigadeMemberAvailabilityAvailable),
	})
	assertMemberEvent(t, db, brigade, added.Member.ID, "BrigadeMemberAvailabilityChanged", map[string]any{
		"role":                string(models.BrigadeMemberRoleDriver),
		"active":              true,
		"member_status":       "ACTIVE",
		"availability_status": string(models.BrigadeMemberAvailabilityUnavailable),
	})
	assertMemberEvent(t, db, brigade, added.Member.ID, "BrigadeMemberRemoved", map[string]any{
		"role":                string(models.BrigadeMemberRoleDriver),
		"active":              false,
		"member_status":       "REMOVED",
		"availability_status": string(models.BrigadeMemberAvailabilityUnavailable),
	})
}

func assertMemberEvent(t *testing.T, db *pgxpool.Pool, brigade *models.Brigade, memberID uuid.UUID, eventType string, expected map[string]any) {
	t.Helper()
	var eventID string
	var payloadBytes []byte
	if err := db.QueryRow(
		context.Background(),
		`SELECT id::text,payload FROM outbox_events WHERE aggregate_id=$1 AND event_type=$2 ORDER BY created_at DESC LIMIT 1`,
		brigade.ID,
		eventType,
	).Scan(&eventID, &payloadBytes); err != nil {
		t.Fatalf("read %s outbox event: %v", eventType, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("decode %s outbox event: %v", eventType, err)
	}
	expected["event_id"] = eventID
	expected["event_type"] = eventType
	expected["event_version"] = float64(1)
	expected["producer"] = "brigade-service"
	expected["department_id"] = brigade.DepartmentID.String()
	expected["brigade_id"] = brigade.ID.String()
	expected["member_id"] = memberID.String()
	for field, want := range expected {
		if got := payload[field]; got != want {
			t.Errorf("%s payload[%q] = %#v, want %#v", eventType, field, got, want)
		}
	}
	if _, ok := payload["occurred_at"]; !ok {
		t.Errorf("%s payload has no occurred_at", eventType)
	}
}
