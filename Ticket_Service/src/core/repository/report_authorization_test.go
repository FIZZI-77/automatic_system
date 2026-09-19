package repository

import (
	"testing"

	"github.com/google/uuid"
	"ticket/models"
)

func TestCanCreateWorkReportChecksCurrentAssignedBrigade(t *testing.T) {
	assigned := uuid.New()
	other := uuid.New()
	worker := &models.CreateWorkReportInput{ActorRoles: []string{"worker"}, ActorBrigadeID: &assigned}
	if !canCreateWorkReport(worker, &assigned) {
		t.Fatal("assigned worker should be allowed")
	}
	if canCreateWorkReport(worker, &other) {
		t.Fatal("worker from a stale assignment must be rejected")
	}
	if !canCreateWorkReport(&models.CreateWorkReportInput{ActorRoles: []string{"dispatcher"}}, &other) {
		t.Fatal("dispatcher should be allowed")
	}
}
