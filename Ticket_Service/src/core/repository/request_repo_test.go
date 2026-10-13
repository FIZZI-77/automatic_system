package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"ticket/models"
)

func TestTicketRepo_CreateRequest_MatchesIncidentWithinRadiusAndWindow(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(DBPools{Write: db, Read: db})

	category := createTestCategory(t, repo)
	departmentID := uuid.New()

	first, err := repo.CreateRequest(ctx, newRequestInput(departmentID, category.ID, 55.751244, 37.618423))

	if err != nil {
		t.Fatalf("CreateRequest(first) error = %v, want nil", err)
	}

	second, err := repo.CreateRequest(ctx, newRequestInput(departmentID, category.ID, 55.751744, 37.618423))

	if err != nil {
		t.Fatalf("CreateRequest(second) error = %v, want nil", err)
	}

	if !second.DuplicateMatched {
		t.Error("CreateRequest(second).DuplicateMatched = false, want true")
	}

	if second.Incident.ID != first.Incident.ID {
		t.Errorf(
			"CreateRequest(second).Incident.ID = %s, want %s",
			second.Incident.ID,
			first.Incident.ID,
		)
	}

	if second.Request.IncidentID == nil || *second.Request.IncidentID != first.Incident.ID {
		t.Errorf(
			"CreateRequest(second).Request.IncidentID = %v, want %s",
			second.Request.IncidentID,
			first.Incident.ID,
		)
	}
}

func TestTicketRepo_CreateRequest_CreatesIncidentOutsideWindow(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(DBPools{Write: db, Read: db})

	category := createTestCategory(t, repo)
	departmentID := uuid.New()

	first, err := repo.CreateRequest(ctx, newRequestInput(departmentID, category.ID, 55.751244, 37.618423))

	if err != nil {
		t.Fatalf("CreateRequest(first) error = %v, want nil", err)
	}

	_, err = db.Exec(
		ctx,
		`UPDATE tickets SET created_at = $1 WHERE department_id = $2 AND id = $3`,
		time.Now().UTC().Add(-25*time.Hour),
		first.Incident.DepartmentID,
		first.Incident.ID,
	)

	if err != nil {
		t.Fatalf("expire first incident: %v", err)
	}

	second, err := repo.CreateRequest(ctx, newRequestInput(departmentID, category.ID, 55.751244, 37.618423))

	if err != nil {
		t.Fatalf("CreateRequest(second) error = %v, want nil", err)
	}

	if second.DuplicateMatched {
		t.Error("CreateRequest(second).DuplicateMatched = true, want false")
	}

	if second.Incident.ID == first.Incident.ID {
		t.Errorf("CreateRequest(second).Incident.ID = %s, want a new incident", second.Incident.ID)
	}
}

func TestTicketRepo_CreateRequest_CreatesIncidentOutsideRadius(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(DBPools{Write: db, Read: db})

	category := createTestCategory(t, repo)
	departmentID := uuid.New()

	first, err := repo.CreateRequest(ctx, newRequestInput(departmentID, category.ID, 55.751244, 37.618423))

	if err != nil {
		t.Fatalf("CreateRequest(first) error = %v, want nil", err)
	}

	second, err := repo.CreateRequest(ctx, newRequestInput(departmentID, category.ID, 55.753244, 37.618423))

	if err != nil {
		t.Fatalf("CreateRequest(second) error = %v, want nil", err)
	}

	if second.DuplicateMatched {
		t.Error("CreateRequest(second).DuplicateMatched = true, want false")
	}

	if second.Incident.ID == first.Incident.ID {
		t.Errorf("CreateRequest(second).Incident.ID = %s, want a new incident", second.Incident.ID)
	}
}

func TestTicketRepo_AttachAndDetachRequest(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(DBPools{Write: db, Read: db})

	category := createTestCategory(t, repo)
	departmentID := uuid.New()

	first, err := repo.CreateRequest(ctx, newRequestInput(departmentID, category.ID, 55.751244, 37.618423))

	if err != nil {
		t.Fatalf("CreateRequest(first) error = %v, want nil", err)
	}

	second, err := repo.CreateRequest(ctx, newRequestInput(departmentID, category.ID, 55.753244, 37.618423))

	if err != nil {
		t.Fatalf("CreateRequest(second) error = %v, want nil", err)
	}

	changedBy := uuid.New()
	attached, err := repo.AttachRequest(ctx, &models.AttachRequestInput{
		IncidentID: second.Incident.ID,
		RequestID:  first.Request.ID,
		ChangedBy:  changedBy,
		Reason:     "Same incident confirmed by dispatcher",
	})

	if err != nil {
		t.Fatalf("AttachRequest() error = %v, want nil", err)
	}

	if attached.IncidentID == nil || *attached.IncidentID != second.Incident.ID {
		t.Errorf("AttachRequest().IncidentID = %v, want %s", attached.IncidentID, second.Incident.ID)
	}

	detached, err := repo.DetachRequest(ctx, &models.DetachRequestInput{
		RequestID: first.Request.ID,
		ChangedBy: changedBy,
		Reason:    "Request belongs to another incident",
	})

	if err != nil {
		t.Fatalf("DetachRequest() error = %v, want nil", err)
	}

	if detached.IncidentID != nil {
		t.Errorf("DetachRequest().IncidentID = %v, want nil", detached.IncidentID)
	}
}

func TestTicketRepo_CreateRequest_ReusesExternalRequest(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(DBPools{Write: db, Read: db})

	category := createTestCategory(t, repo)
	externalSystemID := uuid.New()
	externalID := "external-request-42"

	in := newRequestInput(uuid.New(), category.ID, 55.751244, 37.618423)
	in.ExternalSystemID = &externalSystemID
	in.ExternalID = &externalID

	first, err := repo.CreateRequest(ctx, in)

	if err != nil {
		t.Fatalf("CreateRequest(first) error = %v, want nil", err)
	}

	second, err := repo.CreateRequest(ctx, in)

	if err != nil {
		t.Fatalf("CreateRequest(second) error = %v, want nil", err)
	}

	if second.Request.ID != first.Request.ID {
		t.Errorf("CreateRequest(second).Request.ID = %s, want %s", second.Request.ID, first.Request.ID)
	}

	if second.Incident.ID != first.Incident.ID {
		t.Errorf("CreateRequest(second).Incident.ID = %s, want %s", second.Incident.ID, first.Incident.ID)
	}
}

func newRequestInput(
	departmentID uuid.UUID,
	categoryID uuid.UUID,
	latitude float64,
	longitude float64,
) *models.CreateRequestInput {
	return &models.CreateRequestInput{
		DepartmentID: departmentID,
		CategoryID:   categoryID,
		UserID:       uuid.New(),
		Title:        "Street light is not working",
		Description:  "Street light is not working near the building",
		Priority:     models.TicketPriorityMedium,
		Address:      "Main street 1",
		Latitude:     latitude,
		Longitude:    longitude,
	}
}
