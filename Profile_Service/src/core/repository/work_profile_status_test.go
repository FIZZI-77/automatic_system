package repository

import (
	"testing"

	"github.com/google/uuid"
	"profile/models"
)

func TestCanSetWorkProfileStatusUsesLockedProfileOwner(t *testing.T) {
	ownerID := uuid.New()
	otherID := uuid.New()
	details := &models.WorkProfileDetails{UserProfile: &models.UserProfile{UserID: ownerID}}

	if !canSetWorkProfileStatus(details, &models.SetWorkProfileStatusInput{ActorUserID: &ownerID, ActorRoles: []string{"worker"}}) {
		t.Fatal("profile owner should be allowed to request a worker transition")
	}
	if canSetWorkProfileStatus(details, &models.SetWorkProfileStatusInput{ActorUserID: &otherID, ActorRoles: []string{"worker"}}) {
		t.Fatal("another worker must not update a locked profile")
	}
	if !canSetWorkProfileStatus(details, &models.SetWorkProfileStatusInput{ActorUserID: &otherID, ActorRoles: []string{"admin"}}) {
		t.Fatal("admin should be allowed to update a locked profile")
	}
}

func TestWorkerStatusTransitionRejectsAdministrativeSuspensionOverwrite(t *testing.T) {
	if workerStatusTransitionAllowed(models.WorkProfileStatusSuspended, models.WorkProfileStatusOnShift) {
		t.Fatal("worker transition must not overwrite SUSPENDED")
	}
	if !workerStatusTransitionAllowed(models.WorkProfileStatusOffShift, models.WorkProfileStatusOnShift) {
		t.Fatal("OFF_SHIFT -> ON_SHIFT should remain allowed")
	}
}
