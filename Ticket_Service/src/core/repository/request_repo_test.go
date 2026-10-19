package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

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

func TestTicketRepo_MultiDepartmentIncidentClosesAfterAllPartsComplete(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	repo := NewRepository(DBPools{Write: db, Read: db})

	category := createTestCategory(t, repo)
	first := createRequestForTest(t, repo, newRequestInput(
		uuid.New(),
		category.ID,
		55.751244,
		37.618423,
	))
	second := createRequestForTest(t, repo, newRequestInput(
		uuid.New(),
		category.ID,
		55.761244,
		37.618423,
	))
	changedBy := uuid.New()

	attached, err := repo.AttachRequest(ctx, &models.AttachRequestInput{
		IncidentID: first.Incident.ID,
		RequestID:  second.Request.ID,
		ChangedBy:  changedBy,
		Reason:     "Two departments must resolve the same city incident",
	})

	if err != nil {
		t.Fatalf("AttachRequest(cross-department) error = %v, want nil", err)
	}

	if attached.DepartmentID == first.Incident.DepartmentID {
		t.Fatalf(
			"AttachRequest(cross-department).DepartmentID = %s, want department different from %s",
			attached.DepartmentID,
			first.Incident.DepartmentID,
		)
	}

	requests, total, err := repo.ListIncidentRequests(ctx, &models.ListIncidentRequestsInput{
		IncidentID: first.Incident.ID,
		Limit:      100,
	})

	if err != nil {
		t.Fatalf("ListIncidentRequests() error = %v, want nil", err)
	}

	if total != 2 || len(requests) != 2 {
		t.Fatalf("ListIncidentRequests() = %d requests, total %d, want 2 and 2", len(requests), total)
	}

	departments := map[uuid.UUID]struct{}{}

	for _, request := range requests {
		departments[request.DepartmentID] = struct{}{}
	}

	if len(departments) != 2 {
		t.Errorf("ListIncidentRequests() department count = %d, want 2", len(departments))
	}

	setTicketStatusForTest(t, db, first.Incident, models.TicketStatusInProgress)
	setTicketStatusForTest(t, db, first.Request, models.TicketStatusInProgress)
	setTicketStatusForTest(t, db, second.Request, models.TicketStatusInProgress)

	_, err = repo.CompleteTicket(ctx, &models.CompleteTicketInput{
		TicketID:    first.Incident.ID,
		CompletedBy: changedBy,
	})

	if !errors.Is(err, models.ErrIncidentPartsIncomplete) {
		t.Fatalf("CompleteTicket(incident with incomplete parts) error = %v, want %v", err, models.ErrIncidentPartsIncomplete)
	}

	start := make(chan struct{})
	errorsByRequest := make(chan error, 2)
	var workers sync.WaitGroup

	for _, request := range []*models.Ticket{first.Request, second.Request} {
		request := request
		workers.Add(1)

		go func() {
			defer workers.Done()
			<-start

			_, completeErr := repo.CompleteTicket(ctx, &models.CompleteTicketInput{
				TicketID:    request.ID,
				CompletedBy: changedBy,
			})
			errorsByRequest <- completeErr
		}()
	}

	close(start)
	workers.Wait()
	close(errorsByRequest)

	for completeErr := range errorsByRequest {

		if completeErr != nil {
			t.Errorf("CompleteTicket(concurrent part) error = %v, want nil", completeErr)
		}

	}

	incident, err := repo.GetTicketByID(ctx, first.Incident.ID)

	if err != nil {
		t.Fatalf("GetTicketByID(incident) error = %v, want nil", err)
	}

	if incident.Status != models.TicketStatusDone {
		t.Errorf("GetTicketByID(incident).Status = %s, want %s", incident.Status, models.TicketStatusDone)
	}

	if incident.CompletedAt == nil {
		t.Error("GetTicketByID(incident).CompletedAt = nil, want timestamp")
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

func createRequestForTest(
	t *testing.T,
	repo *Repository,
	in *models.CreateRequestInput,
) *models.CreateRequestResult {
	t.Helper()

	result, err := repo.CreateRequest(context.Background(), in)

	if err != nil {
		t.Fatalf("CreateRequest() error = %v, want nil", err)
	}

	return result
}

func setTicketStatusForTest(
	t *testing.T,
	db interface {
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	},
	ticket *models.Ticket,
	status models.TicketStatus,
) {
	t.Helper()

	_, err := db.Exec(
		context.Background(),
		`UPDATE tickets SET status = $1, updated_at = now() WHERE department_id = $2 AND id = $3`,
		status,
		ticket.DepartmentID,
		ticket.ID,
	)

	if err != nil {
		t.Fatalf("setTicketStatusForTest(%s, %s) error = %v, want nil", ticket.ID, status, err)
	}
}
