package service

import (
	"testing"

	"github.com/google/uuid"
	"ticket/models"
)

func TestCreateWorkReportInputValidate(t *testing.T) {
	in := &models.CreateWorkReportInput{TicketID: uuid.New(), AuthorUserID: uuid.New(), Description: " completed ", FileIDs: []uuid.UUID{uuid.New(), uuid.New()}}
	if err := in.Validate(); err != nil {
		t.Fatalf("expected valid report: %v", err)
	}
	if in.Description != "completed" {
		t.Fatalf("description was not normalized")
	}

	in.FileIDs = append(in.FileIDs, in.FileIDs[0])
	if err := in.Validate(); err == nil {
		t.Fatal("expected duplicate file validation error")
	}
}
