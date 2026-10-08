package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"ticket/models"
)

func TestTicketFeedbackIntegration(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()
	ctx := context.Background()
	category := createIntegrationCategory(t, app)
	ownerID := uuid.New()
	ticket := createIntegrationTicket(t, app, category.ID, ownerID)

	_, err := app.service.SubmitTicketFeedback(ctx, &models.SubmitTicketFeedbackInput{
		TicketID: ticket.ID, UserID: ownerID, Rating: 5, ProblemResolved: true, Comment: "Быстро исправили",
	})

	if !errors.Is(err, models.ErrInvalidStatusTransition) {
		t.Fatalf("expected unfinished ticket rejection, got %v", err)
	}

	brigadeID := uuid.New()
	_, err = app.service.AssignBrigade(ctx, &models.AssignBrigadeInput{
		TicketID: ticket.ID, BrigadeID: brigadeID, AssignedBy: uuid.New(), ActorRoles: dispatcherRoles(),
	})

	if err != nil {
		t.Fatalf("assign brigade: %v", err)
	}

	_, err = app.service.ChangeTicketStatus(ctx, &models.ChangeTicketStatusInput{
		TicketID: ticket.ID, NewStatus: models.TicketStatusInProgress, ChangedBy: uuid.New(), ActorRoles: dispatcherRoles(),
	})

	if err != nil {
		t.Fatalf("start work: %v", err)
	}

	_, err = app.service.CompleteTicket(ctx, &models.CompleteTicketInput{
		TicketID: ticket.ID, CompletedBy: uuid.New(), ActorRoles: dispatcherRoles(),
	})

	if err != nil {
		t.Fatalf("complete ticket: %v", err)
	}

	_, err = app.service.SubmitTicketFeedback(ctx, &models.SubmitTicketFeedbackInput{
		TicketID: ticket.ID, UserID: uuid.New(), Rating: 1, Comment: "Не моя заявка",
	})

	if !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("expected owner check, got %v", err)
	}

	_, err = app.service.SubmitTicketFeedback(ctx, &models.SubmitTicketFeedbackInput{
		TicketID: ticket.ID, UserID: ownerID, Rating: 0,
	})

	if !errors.Is(err, models.ErrValidation) {
		t.Fatalf("expected rating validation, got %v", err)
	}

	feedback, err := app.service.SubmitTicketFeedback(ctx, &models.SubmitTicketFeedbackInput{
		TicketID: ticket.ID, UserID: ownerID, Rating: 5, ProblemResolved: true, Comment: "Быстро исправили",
	})

	if err != nil {
		t.Fatalf("submit feedback: %v", err)
	}

	if feedback.Rating != 5 || !feedback.ProblemResolved {
		t.Fatalf("unexpected feedback: %+v", feedback)
	}

	updated, err := app.service.SubmitTicketFeedback(ctx, &models.SubmitTicketFeedbackInput{
		TicketID: ticket.ID, UserID: ownerID, Rating: 4, Comment: "Потребовалась доработка",
	})

	if err != nil {
		t.Fatalf("update feedback: %v", err)
	}

	if !updated.CreatedAt.Equal(feedback.CreatedAt) {
		t.Fatal("update changed original feedback creation time")
	}

	stored, err := app.service.GetTicketFeedback(ctx, &models.GetTicketFeedbackInput{
		TicketID: ticket.ID, ActorID: ownerID,
	})

	if err != nil || stored.Rating != 4 || stored.ProblemResolved {
		t.Fatalf("unexpected stored feedback: %+v, %v", stored, err)
	}

	_, err = app.service.GetTicketFeedback(ctx, &models.GetTicketFeedbackInput{
		TicketID: ticket.ID, ActorID: uuid.New(),
	})

	if !errors.Is(err, models.ErrNotFound) {
		t.Fatalf("expected private feedback, got %v", err)
	}

	var events int

	if err = app.db.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE aggregate_id=$1 AND event_type='ticket.feedback_submitted'`, ticket.ID).Scan(&events); err != nil {
		t.Fatalf("count feedback events: %v", err)
	}

	if events != 2 {
		t.Fatalf("expected two feedback events, got %d", events)
	}

}
