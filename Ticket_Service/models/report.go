package models

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

type WorkReport struct {
	ID           uuid.UUID   `json:"id"`
	TicketID     uuid.UUID   `json:"ticket_id"`
	AuthorUserID uuid.UUID   `json:"author_user_id"`
	Description  string      `json:"description"`
	FileIDs      []uuid.UUID `json:"file_ids"`
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
}

type CreateWorkReportInput struct {
	TicketID       uuid.UUID
	AuthorUserID   uuid.UUID
	Description    string
	FileIDs        []uuid.UUID
	ActorBrigadeID *uuid.UUID
	ActorRoles     []string
}

func (in *CreateWorkReportInput) Validate() error {
	in.Description = strings.TrimSpace(in.Description)
	if in.TicketID == uuid.Nil || in.AuthorUserID == uuid.Nil {
		return errors.New("ticket_id and author_user_id are required")
	}
	if len(in.Description) == 0 || len(in.Description) > 4000 {
		return errors.New("description must contain 1..4000 characters")
	}
	if len(in.FileIDs) > 20 {
		return errors.New("report may contain at most 20 files")
	}
	seen := make(map[uuid.UUID]struct{}, len(in.FileIDs))
	for _, id := range in.FileIDs {
		if id == uuid.Nil {
			return errors.New("file_id is invalid")
		}
		if _, ok := seen[id]; ok {
			return errors.New("file_ids contain duplicates")
		}
		seen[id] = struct{}{}
	}
	return nil
}
