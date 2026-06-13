package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"ticket/models"
)

func TestTicketRepo_ChangeTicketStatus_ValidTransitionUpdatesTicketAndHistory(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(db)

	category := createTestCategory(t, repo)
	ticket := createTestTicket(t, repo, category.ID)
	changedBy := uuid.New()
	comment := "assigned to queue"

	updated, err := repo.ChangeTicketStatus(ctx, &models.ChangeTicketStatusInput{
		TicketID:  ticket.ID,
		NewStatus: models.TicketStatusAssigned,
		ChangedBy: changedBy,
		Comment:   &comment,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if updated.Status != models.TicketStatusAssigned {
		t.Fatalf("expected ticket status ASSIGNED, got %s", updated.Status)
	}

	history, total, err := repo.GetTicketStatusHistory(ctx, &models.GetTicketStatusHistoryInput{
		TicketID: ticket.ID,
		Limit:    10,
		Offset:   0,
	})
	if err != nil {
		t.Fatalf("failed to get status history: %v", err)
	}

	if total != 2 {
		t.Fatalf("expected total history 2, got %d", total)
	}

	var transition *models.TicketStatusHistory
	for _, item := range history {
		if item.NewStatus == models.TicketStatusAssigned {
			transition = item
			break
		}
	}

	if transition == nil {
		t.Fatal("expected ASSIGNED transition in history")
	}

	if transition.OldStatus == nil || *transition.OldStatus != models.TicketStatusNew {
		t.Fatal("expected old status NEW")
	}
}

func TestTicketRepo_CreateGetListUpdateTicket_CommonFlow(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(db)

	category := createTestCategory(t, repo)
	ticket := createTestTicket(t, repo, category.ID)

	stored, err := repo.GetTicketByID(ctx, ticket.ID)
	if err != nil {
		t.Fatalf("failed to get ticket: %v", err)
	}

	if stored.Status != models.TicketStatusNew {
		t.Fatalf("expected status NEW, got %s", stored.Status)
	}

	status := models.TicketStatusNew
	priority := models.TicketPriorityMedium
	tickets, total, err := repo.ListTickets(ctx, &models.ListTicketsInput{
		DepartmentID: &ticket.DepartmentID,
		Status:       &status,
		Priority:     &priority,
		Limit:        10,
		Offset:       0,
		SortBy:       models.TicketSortByCreatedAt,
		SortOrder:    models.SortOrderDesc,
	})
	if err != nil {
		t.Fatalf("failed to list tickets: %v", err)
	}

	if total != 1 {
		t.Fatalf("expected total 1, got %d", total)
	}

	if len(tickets) != 1 {
		t.Fatalf("expected 1 ticket, got %d", len(tickets))
	}

	title := "Updated pipe leak"
	latitude := 55.8
	longitude := 37.7

	updated, err := repo.UpdateTicket(ctx, &models.UpdateTicketInput{
		TicketID:  ticket.ID,
		Title:     &title,
		Latitude:  &latitude,
		Longitude: &longitude,
		UpdatedBy: &ticket.UserID,
	})
	if err != nil {
		t.Fatalf("failed to update ticket: %v", err)
	}

	if updated.Title != title {
		t.Fatalf("expected title %s, got %s", title, updated.Title)
	}

	if updated.Latitude != latitude {
		t.Fatalf("expected latitude %f, got %f", latitude, updated.Latitude)
	}

	if updated.Longitude != longitude {
		t.Fatalf("expected longitude %f, got %f", longitude, updated.Longitude)
	}
}

func TestTicketRepo_UpdateTicket_NonAuthorReturnsPermissionDenied(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(db)

	category := createTestCategory(t, repo)
	ticket := createTestTicket(t, repo, category.ID)
	otherUserID := uuid.New()
	title := "Malicious update"

	updated, err := repo.UpdateTicket(ctx, &models.UpdateTicketInput{
		TicketID:  ticket.ID,
		Title:     &title,
		UpdatedBy: &otherUserID,
	})

	if updated != nil {
		t.Fatal("expected nil ticket")
	}

	if !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("expected permission denied error, got %v", err)
	}

	stored, err := repo.GetTicketByID(ctx, ticket.ID)
	if err != nil {
		t.Fatalf("failed to get ticket: %v", err)
	}

	if stored.Title == title {
		t.Fatal("expected title to remain unchanged")
	}
}

func TestTicketRepo_CreateTicket_InactiveCategoryReturnsDomainError(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(db)

	category := createTestCategory(t, repo)
	isActive := false

	_, err := repo.UpdateCategory(ctx, &models.UpdateCategoryInput{
		CategoryID: category.ID,
		IsActive:   &isActive,
	})
	if err != nil {
		t.Fatalf("failed to deactivate category: %v", err)
	}

	ticket, err := repo.CreateTicket(ctx, &models.CreateTicketInput{
		DepartmentID: uuid.New(),
		CategoryID:   category.ID,
		UserID:       uuid.New(),
		Title:        "Pipe leak",
		Description:  "Pipe leak in basement",
		Priority:     models.TicketPriorityMedium,
		Address:      "Main street 1",
		Latitude:     55.7,
		Longitude:    37.6,
	})

	if ticket != nil {
		t.Fatal("expected nil ticket")
	}

	if !errors.Is(err, models.ErrCategoryInactive) {
		t.Fatalf("expected category inactive error, got %v", err)
	}
}

func TestTicketRepo_ChangeTicketStatus_InvalidTransitionReturnsDomainError(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(db)

	category := createTestCategory(t, repo)
	ticket := createTestTicket(t, repo, category.ID)

	updated, err := repo.ChangeTicketStatus(ctx, &models.ChangeTicketStatusInput{
		TicketID:  ticket.ID,
		NewStatus: models.TicketStatusDone,
		ChangedBy: uuid.New(),
	})

	if updated != nil {
		t.Fatal("expected nil ticket")
	}

	if !errors.Is(err, models.ErrInvalidStatusTransition) {
		t.Fatalf("expected invalid status transition error, got %v", err)
	}

	stored, err := repo.GetTicketByID(ctx, ticket.ID)
	if err != nil {
		t.Fatalf("failed to get ticket: %v", err)
	}

	if stored.Status != models.TicketStatusNew {
		t.Fatalf("expected ticket to remain NEW, got %s", stored.Status)
	}
}

func TestTicketRepo_AssignComplete_CommonFlow(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(db)

	category := createTestCategory(t, repo)
	ticket := createTestTicket(t, repo, category.ID)
	brigadeID := uuid.New()

	assigned, err := repo.AssignBrigade(ctx, &models.AssignBrigadeInput{
		TicketID:   ticket.ID,
		BrigadeID:  brigadeID,
		AssignedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("expected assign to succeed, got %v", err)
	}

	if assigned.BrigadeID == nil || *assigned.BrigadeID != brigadeID {
		t.Fatal("expected assigned brigade")
	}

	if assigned.AssignedAt == nil {
		t.Fatal("expected assigned_at not nil")
	}

	inProgress, err := repo.ChangeTicketStatus(ctx, &models.ChangeTicketStatusInput{
		TicketID:  ticket.ID,
		NewStatus: models.TicketStatusInProgress,
		ChangedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("expected in progress transition to succeed, got %v", err)
	}

	if inProgress.Status != models.TicketStatusInProgress {
		t.Fatalf("expected IN_PROGRESS, got %s", inProgress.Status)
	}

	completed, err := repo.CompleteTicket(ctx, &models.CompleteTicketInput{
		TicketID:    ticket.ID,
		CompletedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("expected complete to succeed, got %v", err)
	}

	if completed.Status != models.TicketStatusDone {
		t.Fatalf("expected DONE, got %s", completed.Status)
	}

	if completed.CompletedAt == nil {
		t.Fatal("expected completed_at not nil")
	}
}

func TestTicketRepo_ChangeTicketStatus_TerminalTicketCannotBeChanged(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(db)

	category := createTestCategory(t, repo)
	ticket := createTestTicket(t, repo, category.ID)

	_, err := repo.CancelTicket(ctx, &models.CancelTicketInput{
		TicketID:   ticket.ID,
		CanceledBy: uuid.New(),
		Reason:     "duplicate",
	})
	if err != nil {
		t.Fatalf("expected cancel to succeed, got %v", err)
	}

	updated, err := repo.ChangeTicketStatus(ctx, &models.ChangeTicketStatusInput{
		TicketID:  ticket.ID,
		NewStatus: models.TicketStatusAssigned,
		ChangedBy: uuid.New(),
	})

	if updated != nil {
		t.Fatal("expected nil ticket")
	}

	if !errors.Is(err, models.ErrTicketTerminalState) {
		t.Fatalf("expected terminal state error, got %v", err)
	}

	stored, err := repo.GetTicketByID(ctx, ticket.ID)
	if err != nil {
		t.Fatalf("failed to get ticket: %v", err)
	}

	if stored.Status != models.TicketStatusCanceled {
		t.Fatalf("expected ticket to remain CANCELED, got %s", stored.Status)
	}
}

func TestTicketRepo_AssignBrigade_TerminalTicketCannotBeChanged(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(db)

	category := createTestCategory(t, repo)
	ticket := createTestTicket(t, repo, category.ID)

	_, err := repo.CancelTicket(ctx, &models.CancelTicketInput{
		TicketID:   ticket.ID,
		CanceledBy: uuid.New(),
		Reason:     "not needed",
	})
	if err != nil {
		t.Fatalf("expected cancel to succeed, got %v", err)
	}

	assigned, err := repo.AssignBrigade(ctx, &models.AssignBrigadeInput{
		TicketID:   ticket.ID,
		BrigadeID:  uuid.New(),
		AssignedBy: uuid.New(),
	})

	if assigned != nil {
		t.Fatal("expected nil ticket")
	}

	if !errors.Is(err, models.ErrTicketTerminalState) {
		t.Fatalf("expected terminal state error, got %v", err)
	}
}
