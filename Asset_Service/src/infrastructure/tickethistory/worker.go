package tickethistory

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"asset/models"
	"asset/src/core/repository"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

type ticketEvent struct {
	ID         uuid.UUID  `json:"id"`
	TicketID   uuid.UUID  `json:"ticket_id"`
	IncidentID *uuid.UUID `json:"incident_id"`
	AssetID    *uuid.UUID `json:"asset_id"`
	CategoryID uuid.UUID  `json:"category_id"`
	Title      string     `json:"title"`
	Priority   string     `json:"priority"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// Run переносит связанные инциденты из событий Ticket Service в историю объектов.
// При временной ошибке записи смещение не подтверждается.
func Run(ctx context.Context, reader *kafka.Reader, repo *repository.AssetRepoStruct, logger *zap.Logger) {
	for ctx.Err() == nil {
		message, err := reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() == nil {
				logger.Warn("read ticket event", zap.Error(err))
				wait(ctx)
			}
			continue
		}

		incident, err := incidentFromMessage(message)
		if err != nil {
			logger.Warn("invalid ticket event for asset history", zap.Int64("offset", message.Offset), zap.Error(err))
		}
		if incident != nil {
			for ctx.Err() == nil {
				writeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				err = repo.RecordTicketIncident(writeCtx, *incident)
				cancel()
				if err == nil || repository.IsNotFound(err) {
					break
				}
				logger.Warn("write ticket to asset history", zap.Stringer("asset_id", incident.AssetID), zap.Error(err))
				wait(ctx)
			}
		}
		for ctx.Err() == nil {
			if err := reader.CommitMessages(ctx, message); err == nil {
				break
			} else {
				logger.Warn("commit asset history offset", zap.Error(err))
			}
			wait(ctx)
		}
	}
}

func wait(ctx context.Context) {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func incidentFromMessage(message kafka.Message) (*models.Incident, error) {
	var kind string
	for _, header := range message.Headers {
		if header.Key == "event_type" {
			kind = string(header.Value)
			break
		}
	}
	switch kind {
	case "ticket.created", "ticket.updated", "ticket.completed", "ticket.request_attached":
	default:
		return nil, nil
	}

	var event ticketEvent
	if err := json.Unmarshal(message.Value, &event); err != nil {
		return nil, fmt.Errorf("decode ticket: %w", err)
	}
	if event.AssetID == nil || *event.AssetID == uuid.Nil {
		return nil, nil
	}

	id := event.ID
	if id == uuid.Nil {
		id = event.TicketID
	}
	if event.IncidentID != nil {
		id = *event.IncidentID
	}
	if id == uuid.Nil {
		return nil, fmt.Errorf("ticket event has no incident or ticket id")
	}

	at := event.UpdatedAt
	if at.IsZero() {
		at = event.CreatedAt
	}
	if at.IsZero() {
		at = message.Time
	}
	title := event.Title
	if title == "" {
		title = "Инцидент по заявке"
	}
	failureType := "ticket"
	if event.CategoryID != uuid.Nil {
		failureType = event.CategoryID.String()
	}

	return &models.Incident{
		AssetID: *event.AssetID, TicketID: &id, FailureType: failureType, Description: title,
		Source: "TICKET", Priority: event.Priority, OccurredAt: at,
	}, nil
}
