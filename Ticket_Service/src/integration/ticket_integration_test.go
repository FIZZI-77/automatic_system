package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"ticket/models"
)

func TestTicketServiceIntegration_TicketLifecycle(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()

	category := createIntegrationCategory(t, app)
	userID := uuid.New()
	ticket := createIntegrationTicket(t, app, category.ID, userID)

	if ticket.Status != models.TicketStatusNew {
		t.Fatalf("expected new ticket status, got %s", ticket.Status)
	}

	getResult, err := app.service.GetTicket(ctx, &models.GetTicketInput{
		TicketID:    ticket.ID,
		ActorUserID: &userID,
	})
	if err != nil {
		t.Fatalf("get own ticket failed: %v", err)
	}

	if getResult.Ticket.ID != ticket.ID {
		t.Fatalf("expected ticket id %s, got %s", ticket.ID, getResult.Ticket.ID)
	}

	updatedTitle := "Updated street light outage"
	updatedBy := userID
	updateResult, err := app.service.UpdateTicket(ctx, &models.UpdateTicketInput{
		TicketID:  ticket.ID,
		Title:     &updatedTitle,
		UpdatedBy: &updatedBy,
	})
	if err != nil {
		t.Fatalf("update own ticket failed: %v", err)
	}

	if updateResult.Ticket.Title != updatedTitle {
		t.Fatalf("expected title %q, got %q", updatedTitle, updateResult.Ticket.Title)
	}

	brigadeID := uuid.New()
	assignResult, err := app.service.AssignBrigade(ctx, &models.AssignBrigadeInput{
		TicketID:   ticket.ID,
		BrigadeID:  brigadeID,
		AssignedBy: uuid.New(),
		Comment:    stringPtr("Assigned by dispatcher"),
		ActorRoles: dispatcherRoles(),
	})
	if err != nil {
		t.Fatalf("assign brigade failed: %v", err)
	}

	if assignResult.Ticket.BrigadeID == nil || *assignResult.Ticket.BrigadeID != brigadeID {
		t.Fatalf("expected brigade id %s, got %v", brigadeID, assignResult.Ticket.BrigadeID)
	}

	statusResult, err := app.service.ChangeTicketStatus(ctx, &models.ChangeTicketStatusInput{
		TicketID:   ticket.ID,
		NewStatus:  models.TicketStatusInProgress,
		ChangedBy:  uuid.New(),
		Comment:    stringPtr("Work started"),
		ActorRoles: dispatcherRoles(),
	})
	if err != nil {
		t.Fatalf("change status failed: %v", err)
	}

	if statusResult.Ticket.Status != models.TicketStatusInProgress {
		t.Fatalf("expected in progress status, got %s", statusResult.Ticket.Status)
	}

	completeResult, err := app.service.CompleteTicket(ctx, &models.CompleteTicketInput{
		TicketID:    ticket.ID,
		CompletedBy: uuid.New(),
		Comment:     stringPtr("Resolved"),
		ActorRoles:  dispatcherRoles(),
	})
	if err != nil {
		t.Fatalf("complete ticket failed: %v", err)
	}

	if completeResult.Ticket.Status != models.TicketStatusDone {
		t.Fatalf("expected done status, got %s", completeResult.Ticket.Status)
	}

	historyResult, err := app.service.GetTicketStatusHistory(ctx, &models.GetTicketStatusHistoryInput{
		TicketID:    ticket.ID,
		ActorUserID: &userID,
		Limit:       20,
	})
	if err != nil {
		t.Fatalf("get status history failed: %v", err)
	}

	if historyResult.Total < 3 {
		t.Fatalf("expected at least 3 status history records, got %d", historyResult.Total)
	}
}

func TestTicketServiceIntegration_UserPermissions(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()

	category := createIntegrationCategory(t, app)
	ownerID := uuid.New()
	otherUserID := uuid.New()
	ticket := createIntegrationTicket(t, app, category.ID, ownerID)

	_, err := app.service.GetTicket(ctx, &models.GetTicketInput{
		TicketID:    ticket.ID,
		ActorUserID: &otherUserID,
	})
	if !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("expected permission denied for other user, got %v", err)
	}

	listResult, err := app.service.ListTickets(ctx, &models.ListTicketsInput{
		UserID:      &otherUserID,
		ActorUserID: &ownerID,
		Limit:       20,
	})
	if err != nil {
		t.Fatalf("list own tickets failed: %v", err)
	}

	if listResult.Total != 1 {
		t.Fatalf("expected non-privileged list to be scoped to actor with total 1, got %d", listResult.Total)
	}

	_, err = app.service.AssignBrigade(ctx, &models.AssignBrigadeInput{
		TicketID:   ticket.ID,
		BrigadeID:  uuid.New(),
		AssignedBy: ownerID,
	})
	if !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("expected permission denied for assigning brigade without privileged role, got %v", err)
	}

	cancelResult, err := app.service.CancelTicket(ctx, &models.CancelTicketInput{
		TicketID:   ticket.ID,
		CanceledBy: ownerID,
		Reason:     "No longer needed",
	})
	if err != nil {
		t.Fatalf("owner cancel failed: %v", err)
	}

	if cancelResult.Ticket.Status != models.TicketStatusCanceled {
		t.Fatalf("expected canceled status, got %s", cancelResult.Ticket.Status)
	}
}

func TestTicketServiceIntegration_CategoryActiveFlagAndFilters(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()

	category := createIntegrationCategory(t, app)

	updateResult, err := app.service.UpdateCategory(ctx, &models.UpdateCategoryInput{
		CategoryID: category.ID,
		IsActive:   boolPtr(false),
		ActorRoles: adminRoles(),
	})
	if err != nil {
		t.Fatalf("deactivate category failed: %v", err)
	}

	if updateResult.Category.IsActive {
		t.Fatal("expected category to be inactive after update")
	}

	allResult, err := app.service.ListCategories(ctx, &models.ListCategoriesInput{
		OnlyActive: false,
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("list all categories failed: %v", err)
	}

	foundInactive := false
	for _, item := range allResult.Categories {
		if item.ID == category.ID {
			foundInactive = !item.IsActive
		}
	}

	if !foundInactive {
		t.Fatal("expected inactive category to be present when only_active is false")
	}

	activeResult, err := app.service.ListCategories(ctx, &models.ListCategoriesInput{
		OnlyActive: true,
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("list active categories failed: %v", err)
	}

	for _, item := range activeResult.Categories {
		if item.ID == category.ID {
			t.Fatal("expected inactive category to be absent when only_active is true")
		}
	}
}

func TestTicketServiceIntegration_CategoryMutationsRequirePrivilegedRole(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()

	_, err := app.service.CreateCategory(ctx, &models.CreateCategoryInput{
		Code:        uniqueCode("denied-category"),
		Name:        "Denied category",
		Description: stringPtr("Should not be created"),
	})
	if !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("expected permission denied for create category, got %v", err)
	}

	category := createIntegrationCategory(t, app)

	_, err = app.service.UpdateCategory(ctx, &models.UpdateCategoryInput{
		CategoryID: category.ID,
		Name:       stringPtr("Denied update"),
	})
	if !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("expected permission denied for update category, got %v", err)
	}

	_, err = app.service.DeleteCategory(ctx, &models.DeleteCategoryInput{
		CategoryID: category.ID,
	})
	if !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("expected permission denied for delete category, got %v", err)
	}
}
