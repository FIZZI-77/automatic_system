package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"ticket/models"
)

func (t *TicketRepoStruct) SubmitTicketFeedback(ctx context.Context, in *models.SubmitTicketFeedbackInput) (*models.TicketFeedback, error) {

	if in.Rating < 1 || in.Rating > 5 || len([]rune(in.Comment)) > 1000 {
		return nil, fmt.Errorf("%w: rating must be 1-5 and comment at most 1000 characters", models.ErrValidation)
	}

	comment := strings.TrimSpace(in.Comment)
	tx, err := t.writePool.BeginTx(ctx, pgx.TxOptions{})

	if err != nil {
		return nil, err
	}

	defer tx.Rollback(ctx)

	var departmentID, categoryID, ownerID uuid.UUID
	var status string
	err = tx.QueryRow(ctx, `SELECT department_id FROM tickets WHERE id=$1`, in.TicketID).Scan(&departmentID)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrNotFound
	}

	if err != nil {
		return nil, err
	}

	err = tx.QueryRow(ctx, `SELECT category_id,user_id,status FROM tickets WHERE department_id=$1 AND id=$2 FOR UPDATE`, departmentID, in.TicketID).Scan(&categoryID, &ownerID, &status)

	if err != nil {
		return nil, err
	}

	if ownerID != in.UserID {
		return nil, models.ErrPermissionDenied
	}

	if status != string(models.TicketStatusDone) {
		return nil, fmt.Errorf("%w: ticket must be completed", models.ErrInvalidStatusTransition)
	}

	feedback := &models.TicketFeedback{TicketID: in.TicketID, UserID: in.UserID, Rating: in.Rating, ProblemResolved: in.ProblemResolved, Comment: comment}
	err = tx.QueryRow(ctx, `UPDATE tickets SET feedback_rating=$3,feedback_resolved=$4,feedback_comment=$5,feedback_created_at=COALESCE(feedback_created_at,now()),feedback_updated_at=now() WHERE department_id=$1 AND id=$2 RETURNING feedback_created_at,feedback_updated_at`, departmentID, in.TicketID, in.Rating, in.ProblemResolved, comment).Scan(&feedback.CreatedAt, &feedback.UpdatedAt)

	if err != nil {
		return nil, err
	}

	eventID := uuid.New()
	payload, err := json.Marshal(map[string]any{
		"event_id": eventID, "event_type": "ticket.feedback_submitted", "ticket_id": in.TicketID,
		"department_id": departmentID, "category_id": categoryID, "user_id": in.UserID,
		"rating": in.Rating, "problem_resolved": in.ProblemResolved, "occurred_at": feedback.UpdatedAt.Format(time.RFC3339Nano),
	})

	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload,status,attempts,created_at) VALUES($1,'ticket',$2,'ticket.feedback_submitted',$3::jsonb,'PENDING',0,now())`, eventID, in.TicketID, string(payload))

	if err != nil {
		return nil, err
	}

	return feedback, tx.Commit(ctx)
}

func (t *TicketRepoStruct) GetTicketFeedback(ctx context.Context, in *models.GetTicketFeedbackInput) (*models.TicketFeedback, error) {
	feedback := &models.TicketFeedback{TicketID: in.TicketID}
	err := t.readPool.QueryRow(ctx, `SELECT user_id,feedback_rating,feedback_resolved,feedback_comment,feedback_created_at,feedback_updated_at FROM tickets WHERE id=$1 AND (user_id=$2 OR $3) AND feedback_rating IS NOT NULL`, in.TicketID, in.ActorID, in.Privileged).Scan(&feedback.UserID, &feedback.Rating, &feedback.ProblemResolved, &feedback.Comment, &feedback.CreatedAt, &feedback.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrNotFound
	}

	return feedback, err
}
