package handlers

import (
	"context"
	"net/http"
	"time"

	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/gin-gonic/gin"

	"gateway/models"
)

func (th *TicketHandler) SubmitFeedback(c *gin.Context) {
	var request models.SubmitTicketFeedbackRequest

	if !bindJSON(c, &request) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	response, err := th.ticketClient.SubmitTicketFeedback(ticketActorContext(ctx, c), &ticketv1.SubmitTicketFeedbackRequest{
		TicketId: request.TicketID, Rating: request.Rating, ProblemResolved: request.ProblemResolved, Comment: request.Comment,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, feedbackFromProto(response.GetFeedback()))
}

func (th *TicketHandler) GetFeedback(c *gin.Context) {
	var request models.GetTicketFeedbackRequest

	if !bindJSON(c, &request) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	response, err := th.ticketClient.GetTicketFeedback(ticketActorContext(ctx, c), &ticketv1.GetTicketFeedbackRequest{TicketId: request.TicketID})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, feedbackFromProto(response.GetFeedback()))
}

func feedbackFromProto(value *ticketv1.TicketFeedback) *models.TicketFeedback {
	if value == nil {
		return nil
	}

	return &models.TicketFeedback{
		TicketID: value.GetTicketId(), UserID: value.GetUserId(), Rating: value.GetRating(),
		ProblemResolved: value.GetProblemResolved(), Comment: value.GetComment(),
		CreatedAt: value.GetCreatedAt().AsTime(), UpdatedAt: value.GetUpdatedAt().AsTime(),
	}
}
