package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"ticket/models"
	"ticket/src/core/repository"
)

type mockRequestRepository struct {
	attachRequestFunc         func(context.Context, *models.AttachRequestInput) (*models.Ticket, error)
	incidentHasDepartmentFunc func(context.Context, uuid.UUID, *uuid.UUID) (bool, error)
	listIncidentRequestsFunc  func(context.Context, *models.ListIncidentRequestsInput) ([]*models.Ticket, int64, error)
}

func (m *mockRequestRepository) CreateRequest(
	context.Context,
	*models.CreateRequestInput,
) (*models.CreateRequestResult, error) {
	return nil, nil
}

func (m *mockRequestRepository) AttachRequest(
	ctx context.Context,
	in *models.AttachRequestInput,
) (*models.Ticket, error) {
	return m.attachRequestFunc(ctx, in)
}

func (m *mockRequestRepository) DetachRequest(
	context.Context,
	*models.DetachRequestInput,
) (*models.Ticket, error) {
	return nil, nil
}

func (m *mockRequestRepository) ListIncidentRequests(
	ctx context.Context,
	in *models.ListIncidentRequestsInput,
) ([]*models.Ticket, int64, error) {
	return m.listIncidentRequestsFunc(ctx, in)
}

func (m *mockRequestRepository) IncidentHasDepartment(
	ctx context.Context,
	incidentID uuid.UUID,
	departmentID *uuid.UUID,
) (bool, error) {
	return m.incidentHasDepartmentFunc(ctx, incidentID, departmentID)
}

func TestRequestService_AttachRequest_AllowsDispatcherWhoOwnsCrossDepartmentPart(t *testing.T) {
	t.Parallel()

	incident := &models.Ticket{
		ID:           uuid.New(),
		DepartmentID: uuid.New(),
		Type:         models.TicketTypeIncident,
	}
	request := &models.Ticket{
		ID:           uuid.New(),
		DepartmentID: uuid.New(),
		Type:         models.TicketTypeRequest,
	}
	dispatcherDepartmentID := request.DepartmentID

	ticketRepo := &mockTicketRepo{
		getTicketByIDFunc: func(_ context.Context, ticketID uuid.UUID) (*models.Ticket, error) {
			if ticketID == incident.ID {
				return incident, nil
			}

			return request, nil
		},
	}
	requestRepo := &mockRequestRepository{
		attachRequestFunc: func(_ context.Context, in *models.AttachRequestInput) (*models.Ticket, error) {
			attached := *request
			attached.IncidentID = &in.IncidentID

			return &attached, nil
		},
	}
	service := NewTicketServiceStruct(&repository.Repository{
		TicketRepository:  ticketRepo,
		RequestRepository: requestRepo,
	}, zap.NewNop())

	attached, err := service.AttachRequest(context.Background(), &models.AttachRequestInput{
		IncidentID:        incident.ID,
		RequestID:         request.ID,
		ChangedBy:         uuid.New(),
		Reason:            "Same city incident",
		ActorDepartmentID: &dispatcherDepartmentID,
		ActorRoles:        []string{"dispatcher"},
	})

	if err != nil {
		t.Fatalf("AttachRequest(cross-department dispatcher) error = %v, want nil", err)
	}

	if attached.IncidentID == nil || *attached.IncidentID != incident.ID {
		t.Errorf("AttachRequest(cross-department dispatcher).IncidentID = %v, want %s", attached.IncidentID, incident.ID)
	}
}

func TestRequestService_ListIncidentRequests_AllowsDispatcherWhoseDepartmentHasPart(t *testing.T) {
	t.Parallel()

	incident := &models.Ticket{
		ID:           uuid.New(),
		DepartmentID: uuid.New(),
		Type:         models.TicketTypeIncident,
	}
	dispatcherDepartmentID := uuid.New()
	part := &models.Ticket{
		ID:           uuid.New(),
		DepartmentID: dispatcherDepartmentID,
		Type:         models.TicketTypeRequest,
		IncidentID:   &incident.ID,
	}

	ticketRepo := &mockTicketRepo{
		getTicketByIDFunc: func(context.Context, uuid.UUID) (*models.Ticket, error) {
			return incident, nil
		},
	}
	requestRepo := &mockRequestRepository{
		incidentHasDepartmentFunc: func(
			context.Context,
			uuid.UUID,
			*uuid.UUID,
		) (bool, error) {
			return true, nil
		},
		listIncidentRequestsFunc: func(
			context.Context,
			*models.ListIncidentRequestsInput,
		) ([]*models.Ticket, int64, error) {
			return []*models.Ticket{part}, 1, nil
		},
	}
	service := NewTicketServiceStruct(&repository.Repository{
		TicketRepository:  ticketRepo,
		RequestRepository: requestRepo,
	}, zap.NewNop())

	parts, total, err := service.ListIncidentRequests(context.Background(), &models.ListIncidentRequestsInput{
		IncidentID:        incident.ID,
		Limit:             100,
		ActorDepartmentID: &dispatcherDepartmentID,
		ActorRoles:        []string{"dispatcher"},
	})

	if err != nil {
		t.Fatalf("ListIncidentRequests(part department dispatcher) error = %v, want nil", err)
	}

	if total != 1 || len(parts) != 1 || parts[0].ID != part.ID {
		t.Errorf("ListIncidentRequests(part department dispatcher) = (%v, %d), want part %s and total 1", parts, total, part.ID)
	}
}
