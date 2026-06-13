package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"ticket/models"
	"ticket/src/core/repository"
)

type mockTicketRepo struct {
	createTicketFunc           func(ctx context.Context, in *models.CreateTicketInput) (*models.Ticket, error)
	getTicketByIDFunc          func(ctx context.Context, ticketID uuid.UUID) (*models.Ticket, error)
	listTicketsFunc            func(ctx context.Context, in *models.ListTicketsInput) ([]*models.Ticket, int64, error)
	updateTicketFunc           func(ctx context.Context, in *models.UpdateTicketInput) (*models.Ticket, error)
	changeTicketStatusFunc     func(ctx context.Context, in *models.ChangeTicketStatusInput) (*models.Ticket, error)
	assignBrigadeFunc          func(ctx context.Context, in *models.AssignBrigadeInput) (*models.Ticket, error)
	cancelTicketFunc           func(ctx context.Context, in *models.CancelTicketInput) (*models.Ticket, error)
	completeTicketFunc         func(ctx context.Context, in *models.CompleteTicketInput) (*models.Ticket, error)
	getTicketStatusHistoryFunc func(ctx context.Context, in *models.GetTicketStatusHistoryInput) ([]*models.TicketStatusHistory, int64, error)
}

func (m *mockTicketRepo) CreateTicket(ctx context.Context, in *models.CreateTicketInput) (*models.Ticket, error) {
	return m.createTicketFunc(ctx, in)
}

func (m *mockTicketRepo) GetTicketByID(ctx context.Context, ticketID uuid.UUID) (*models.Ticket, error) {
	return m.getTicketByIDFunc(ctx, ticketID)
}

func (m *mockTicketRepo) ListTickets(ctx context.Context, in *models.ListTicketsInput) ([]*models.Ticket, int64, error) {
	return m.listTicketsFunc(ctx, in)
}

func (m *mockTicketRepo) UpdateTicket(ctx context.Context, in *models.UpdateTicketInput) (*models.Ticket, error) {
	return m.updateTicketFunc(ctx, in)
}

func (m *mockTicketRepo) ChangeTicketStatus(ctx context.Context, in *models.ChangeTicketStatusInput) (*models.Ticket, error) {
	return m.changeTicketStatusFunc(ctx, in)
}

func (m *mockTicketRepo) AssignBrigade(ctx context.Context, in *models.AssignBrigadeInput) (*models.Ticket, error) {
	return m.assignBrigadeFunc(ctx, in)
}

func (m *mockTicketRepo) CancelTicket(ctx context.Context, in *models.CancelTicketInput) (*models.Ticket, error) {
	return m.cancelTicketFunc(ctx, in)
}

func (m *mockTicketRepo) CompleteTicket(ctx context.Context, in *models.CompleteTicketInput) (*models.Ticket, error) {
	return m.completeTicketFunc(ctx, in)
}

func (m *mockTicketRepo) GetTicketStatusHistory(ctx context.Context, in *models.GetTicketStatusHistoryInput) ([]*models.TicketStatusHistory, int64, error) {
	return m.getTicketStatusHistoryFunc(ctx, in)
}

func newTestTicketService(repo *repository.Repository) *TicketServiceStruct {
	return NewTicketServiceStruct(repo, zap.NewNop())
}

func TestTicketService_CreateTicket_Success(t *testing.T) {
	expectedTicket := &models.Ticket{
		ID:           uuid.New(),
		DepartmentID: uuid.New(),
		CategoryID:   uuid.New(),
		UserID:       uuid.New(),
		Title:        "Pipe leak",
		Description:  "Pipe leak in basement",
		Status:       models.TicketStatusNew,
		Priority:     models.TicketPriorityMedium,
		Address:      "Main street 1",
		Latitude:     55.7,
		Longitude:    37.6,
	}

	ticketRepo := &mockTicketRepo{
		createTicketFunc: func(ctx context.Context, in *models.CreateTicketInput) (*models.Ticket, error) {
			if in.DepartmentID != expectedTicket.DepartmentID {
				t.Fatalf("expected department id %s, got %s", expectedTicket.DepartmentID, in.DepartmentID)
			}

			if in.CategoryID != expectedTicket.CategoryID {
				t.Fatalf("expected category id %s, got %s", expectedTicket.CategoryID, in.CategoryID)
			}

			if in.UserID != expectedTicket.UserID {
				t.Fatalf("expected user id %s, got %s", expectedTicket.UserID, in.UserID)
			}

			return expectedTicket, nil
		},
	}

	repo := &repository.Repository{
		TicketRepository: ticketRepo,
	}

	svc := newTestTicketService(repo)

	result, err := svc.CreateTicket(context.Background(), &models.CreateTicketInput{
		DepartmentID: expectedTicket.DepartmentID,
		CategoryID:   expectedTicket.CategoryID,
		UserID:       expectedTicket.UserID,
		ActorUserID:  &expectedTicket.UserID,
		Title:        expectedTicket.Title,
		Description:  expectedTicket.Description,
		Priority:     expectedTicket.Priority,
		Address:      expectedTicket.Address,
		Latitude:     expectedTicket.Latitude,
		Longitude:    expectedTicket.Longitude,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.Ticket.ID != expectedTicket.ID {
		t.Fatalf("expected ticket id %s, got %s", expectedTicket.ID, result.Ticket.ID)
	}
}

func TestTicketService_CreateTicket_CategoryInactivePreserved(t *testing.T) {
	ticketRepo := &mockTicketRepo{
		createTicketFunc: func(ctx context.Context, in *models.CreateTicketInput) (*models.Ticket, error) {
			return nil, models.ErrCategoryInactive
		},
	}

	repo := &repository.Repository{
		TicketRepository: ticketRepo,
	}

	svc := newTestTicketService(repo)

	input := validCreateTicketServiceInput()
	input.ActorRoles = []string{"admin"}

	result, err := svc.CreateTicket(context.Background(), input)

	if result != nil {
		t.Fatal("expected nil result")
	}

	if !errors.Is(err, models.ErrCategoryInactive) {
		t.Fatalf("expected category inactive error, got %v", err)
	}
}

func TestTicketService_ListTickets_DefaultsPagination(t *testing.T) {
	ticketID := uuid.New()
	actorUserID := uuid.New()

	ticketRepo := &mockTicketRepo{
		listTicketsFunc: func(ctx context.Context, in *models.ListTicketsInput) ([]*models.Ticket, int64, error) {
			if in.Limit != models.DefaultLimit {
				t.Fatalf("expected default limit %d, got %d", models.DefaultLimit, in.Limit)
			}

			if in.Offset != 0 {
				t.Fatalf("expected offset 0, got %d", in.Offset)
			}

			if in.UserID == nil || *in.UserID != actorUserID {
				t.Fatalf("expected user filter %s, got %v", actorUserID, in.UserID)
			}

			return []*models.Ticket{{ID: ticketID, Status: models.TicketStatusNew}}, 1, nil
		},
	}

	repo := &repository.Repository{
		TicketRepository: ticketRepo,
	}

	svc := newTestTicketService(repo)

	result, err := svc.ListTickets(context.Background(), &models.ListTicketsInput{
		ActorUserID: &actorUserID,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.Total != 1 {
		t.Fatalf("expected total 1, got %d", result.Total)
	}

	if len(result.Tickets) != 1 {
		t.Fatalf("expected 1 ticket, got %d", len(result.Tickets))
	}
}

func TestTicketService_UpdateTicket_Success(t *testing.T) {
	ticketID := uuid.New()
	updatedBy := uuid.New()
	title := "Updated title"

	ticketRepo := &mockTicketRepo{
		updateTicketFunc: func(ctx context.Context, in *models.UpdateTicketInput) (*models.Ticket, error) {
			if in.TicketID != ticketID {
				t.Fatalf("expected ticket id %s, got %s", ticketID, in.TicketID)
			}

			if in.Title == nil || *in.Title != title {
				t.Fatal("expected updated title")
			}

			if in.UpdatedBy == nil || *in.UpdatedBy != updatedBy {
				t.Fatal("expected updated_by")
			}

			return &models.Ticket{ID: ticketID, Title: title, Status: models.TicketStatusNew}, nil
		},
	}

	repo := &repository.Repository{
		TicketRepository: ticketRepo,
	}

	svc := newTestTicketService(repo)

	result, err := svc.UpdateTicket(context.Background(), &models.UpdateTicketInput{
		TicketID:  ticketID,
		Title:     &title,
		UpdatedBy: &updatedBy,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.Ticket.Title != title {
		t.Fatalf("expected title %s, got %s", title, result.Ticket.Title)
	}
}

func TestTicketService_ChangeTicketStatus_DelegatesToRepoWithoutPreRead(t *testing.T) {
	ticketID := uuid.New()
	changedBy := uuid.New()

	ticketRepo := &mockTicketRepo{
		getTicketByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.Ticket, error) {
			t.Fatal("expected ChangeTicketStatus not to pre-read ticket in service")
			return nil, nil
		},
		changeTicketStatusFunc: func(ctx context.Context, in *models.ChangeTicketStatusInput) (*models.Ticket, error) {
			if in.TicketID != ticketID {
				t.Fatalf("expected ticket id %s, got %s", ticketID, in.TicketID)
			}

			if in.NewStatus != models.TicketStatusAssigned {
				t.Fatalf("expected status ASSIGNED, got %s", in.NewStatus)
			}

			if in.ChangedBy != changedBy {
				t.Fatalf("expected changed_by %s, got %s", changedBy, in.ChangedBy)
			}

			return &models.Ticket{
				ID:     ticketID,
				Status: models.TicketStatusAssigned,
			}, nil
		},
	}

	repo := &repository.Repository{
		TicketRepository: ticketRepo,
	}

	svc := newTestTicketService(repo)

	result, err := svc.ChangeTicketStatus(context.Background(), &models.ChangeTicketStatusInput{
		TicketID:   ticketID,
		NewStatus:  models.TicketStatusAssigned,
		ChangedBy:  changedBy,
		ActorRoles: []string{"admin"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.Ticket.Status != models.TicketStatusAssigned {
		t.Fatalf("expected ticket status ASSIGNED, got %s", result.Ticket.Status)
	}
}

func TestTicketService_ChangeTicketStatus_InvalidInputWrapsValidation(t *testing.T) {
	repo := &repository.Repository{
		TicketRepository: &mockTicketRepo{},
	}

	svc := newTestTicketService(repo)

	result, err := svc.ChangeTicketStatus(context.Background(), &models.ChangeTicketStatusInput{
		NewStatus: models.TicketStatusAssigned,
		ChangedBy: uuid.New(),
	})

	if result != nil {
		t.Fatal("expected nil result")
	}

	if !errors.Is(err, models.ErrValidation) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestTicketService_ChangeTicketStatus_PreservesRepoDomainError(t *testing.T) {
	ticketID := uuid.New()

	ticketRepo := &mockTicketRepo{
		changeTicketStatusFunc: func(ctx context.Context, in *models.ChangeTicketStatusInput) (*models.Ticket, error) {
			return nil, models.ErrInvalidStatusTransition
		},
	}

	repo := &repository.Repository{
		TicketRepository: ticketRepo,
	}

	svc := newTestTicketService(repo)

	result, err := svc.ChangeTicketStatus(context.Background(), &models.ChangeTicketStatusInput{
		TicketID:   ticketID,
		NewStatus:  models.TicketStatusDone,
		ChangedBy:  uuid.New(),
		ActorRoles: []string{"admin"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}

	if !errors.Is(err, models.ErrInvalidStatusTransition) {
		t.Fatalf("expected invalid status transition error, got %v", err)
	}
}

func TestTicketService_AssignCancelComplete_CommonCases(t *testing.T) {
	ticketID := uuid.New()

	t.Run("assign brigade success", func(t *testing.T) {
		brigadeID := uuid.New()
		assignedBy := uuid.New()

		ticketRepo := &mockTicketRepo{
			assignBrigadeFunc: func(ctx context.Context, in *models.AssignBrigadeInput) (*models.Ticket, error) {
				if in.TicketID != ticketID {
					t.Fatalf("expected ticket id %s, got %s", ticketID, in.TicketID)
				}

				if in.BrigadeID != brigadeID {
					t.Fatalf("expected brigade id %s, got %s", brigadeID, in.BrigadeID)
				}

				return &models.Ticket{
					ID:        ticketID,
					BrigadeID: &brigadeID,
					Status:    models.TicketStatusAssigned,
				}, nil
			},
		}

		svc := newTestTicketService(&repository.Repository{TicketRepository: ticketRepo})

		result, err := svc.AssignBrigade(context.Background(), &models.AssignBrigadeInput{
			TicketID:   ticketID,
			BrigadeID:  brigadeID,
			AssignedBy: assignedBy,
			ActorRoles: []string{"dispatcher"},
		})

		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if result.Ticket.Status != models.TicketStatusAssigned {
			t.Fatalf("expected status ASSIGNED, got %s", result.Ticket.Status)
		}
	})

	t.Run("cancel terminal error preserved", func(t *testing.T) {
		canceledBy := uuid.New()

		ticketRepo := &mockTicketRepo{
			getTicketByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.Ticket, error) {
				return &models.Ticket{
					ID:     id,
					UserID: canceledBy,
					Status: models.TicketStatusDone,
				}, nil
			},
			cancelTicketFunc: func(ctx context.Context, in *models.CancelTicketInput) (*models.Ticket, error) {
				return nil, models.ErrTicketTerminalState
			},
		}

		svc := newTestTicketService(&repository.Repository{TicketRepository: ticketRepo})

		result, err := svc.CancelTicket(context.Background(), &models.CancelTicketInput{
			TicketID:   ticketID,
			CanceledBy: canceledBy,
			Reason:     "duplicate",
		})

		if result != nil {
			t.Fatal("expected nil result")
		}

		if !errors.Is(err, models.ErrTicketTerminalState) {
			t.Fatalf("expected terminal state error, got %v", err)
		}
	})

	t.Run("complete validation error", func(t *testing.T) {
		svc := newTestTicketService(&repository.Repository{TicketRepository: &mockTicketRepo{}})

		result, err := svc.CompleteTicket(context.Background(), &models.CompleteTicketInput{
			TicketID: ticketID,
		})

		if result != nil {
			t.Fatal("expected nil result")
		}

		if !errors.Is(err, models.ErrValidation) {
			t.Fatalf("expected validation error, got %v", err)
		}
	})
}

func TestTicketService_AccessRules(t *testing.T) {
	t.Run("create ticket for another user denied", func(t *testing.T) {
		actorUserID := uuid.New()
		input := validCreateTicketServiceInput()
		input.ActorUserID = &actorUserID

		svc := newTestTicketService(&repository.Repository{TicketRepository: &mockTicketRepo{
			createTicketFunc: func(ctx context.Context, in *models.CreateTicketInput) (*models.Ticket, error) {
				t.Fatal("expected repo not to be called")
				return nil, nil
			},
		}})

		result, err := svc.CreateTicket(context.Background(), input)

		if result != nil {
			t.Fatal("expected nil result")
		}

		if !errors.Is(err, models.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("get own ticket allowed", func(t *testing.T) {
		ticketID := uuid.New()
		actorUserID := uuid.New()

		ticketRepo := &mockTicketRepo{
			getTicketByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.Ticket, error) {
				return &models.Ticket{ID: id, UserID: actorUserID}, nil
			},
		}

		svc := newTestTicketService(&repository.Repository{TicketRepository: ticketRepo})

		result, err := svc.GetTicket(context.Background(), &models.GetTicketInput{
			TicketID:    ticketID,
			ActorUserID: &actorUserID,
		})

		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if result.Ticket.ID != ticketID {
			t.Fatalf("expected ticket id %s, got %s", ticketID, result.Ticket.ID)
		}
	})

	t.Run("get another user ticket denied", func(t *testing.T) {
		ticketID := uuid.New()
		actorUserID := uuid.New()

		ticketRepo := &mockTicketRepo{
			getTicketByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.Ticket, error) {
				return &models.Ticket{ID: id, UserID: uuid.New()}, nil
			},
		}

		svc := newTestTicketService(&repository.Repository{TicketRepository: ticketRepo})

		result, err := svc.GetTicket(context.Background(), &models.GetTicketInput{
			TicketID:    ticketID,
			ActorUserID: &actorUserID,
		})

		if result != nil {
			t.Fatal("expected nil result")
		}

		if !errors.Is(err, models.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("change status without privileged role denied", func(t *testing.T) {
		ticketID := uuid.New()

		svc := newTestTicketService(&repository.Repository{TicketRepository: &mockTicketRepo{
			changeTicketStatusFunc: func(ctx context.Context, in *models.ChangeTicketStatusInput) (*models.Ticket, error) {
				t.Fatal("expected repo not to be called")
				return nil, nil
			},
		}})

		result, err := svc.ChangeTicketStatus(context.Background(), &models.ChangeTicketStatusInput{
			TicketID:  ticketID,
			NewStatus: models.TicketStatusAssigned,
			ChangedBy: uuid.New(),
		})

		if result != nil {
			t.Fatal("expected nil result")
		}

		if !errors.Is(err, models.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})
}

func validCreateTicketServiceInput() *models.CreateTicketInput {
	return &models.CreateTicketInput{
		DepartmentID: uuid.New(),
		CategoryID:   uuid.New(),
		UserID:       uuid.New(),
		Title:        "Pipe leak",
		Description:  "Pipe leak in basement",
		Priority:     models.TicketPriorityMedium,
		Address:      "Main street 1",
		Latitude:     55.7,
		Longitude:    37.6,
	}
}
