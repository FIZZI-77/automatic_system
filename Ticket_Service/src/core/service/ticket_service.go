package service

import (
	"context"
	"errors"
	"fmt"

	"ticket/models"
	"ticket/src/core/repository"
)

type TicketServiceStruct struct {
	repo *repository.Repository
}

func NewTicketServiceStruct(repo *repository.Repository) *TicketServiceStruct {
	return &TicketServiceStruct{
		repo: repo,
	}
}

func (s *TicketServiceStruct) CreateTicket(ctx context.Context, in *models.CreateTicketInput) (*models.CreateTicketResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: CreateTicket(): validate: %w", err)
	}

	ticket, err := s.repo.CreateTicket(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: CreateTicket(): %w", err)
	}

	return &models.CreateTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) GetTicket(ctx context.Context, in *models.GetTicketInput) (*models.GetTicketResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: GetTicket(): validate: %w", err)
	}

	ticket, err := s.repo.GetTicketByID(ctx, in.TicketID)
	if err != nil {
		return nil, fmt.Errorf("service: GetTicket(): %w", err)
	}

	return &models.GetTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) ListTickets(ctx context.Context, in *models.ListTicketsInput) (*models.ListTicketsResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: ListTickets(): validate: %w", err)
	}

	tickets, total, err := s.repo.ListTickets(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ListTickets(): %w", err)
	}

	return &models.ListTicketsResult{
		Tickets: tickets,
		Total:   total,
	}, nil
}

func (s *TicketServiceStruct) UpdateTicket(ctx context.Context, in *models.UpdateTicketInput) (*models.UpdateTicketResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: UpdateTicket(): validate: %w", err)
	}

	ticket, err := s.repo.UpdateTicket(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: UpdateTicket(): %w", err)
	}

	return &models.UpdateTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) ChangeTicketStatus(ctx context.Context, in *models.ChangeTicketStatusInput) (*models.ChangeTicketStatusResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: ChangeTicketStatus(): validate: %w", err)
	}

	currentTicket, err := s.repo.GetTicketByID(ctx, in.TicketID)
	if err != nil {
		return nil, fmt.Errorf("service: ChangeTicketStatus(): get ticket: %w", err)
	}

	if err = validateStatusTransition(currentTicket.Status, in.NewStatus); err != nil {
		return nil, fmt.Errorf("service: ChangeTicketStatus(): %w", err)
	}

	ticket, err := s.repo.ChangeTicketStatus(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: ChangeTicketStatus(): %w", err)
	}

	return &models.ChangeTicketStatusResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) AssignBrigade(ctx context.Context, in *models.AssignBrigadeInput) (*models.AssignBrigadeResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: AssignBrigade(): validate: %w", err)
	}

	currentTicket, err := s.repo.GetTicketByID(ctx, in.TicketID)
	if err != nil {
		return nil, fmt.Errorf("service: AssignBrigade(): get ticket: %w", err)
	}

	if err = validateStatusTransition(currentTicket.Status, models.TicketStatusAssigned); err != nil {
		return nil, fmt.Errorf("service: AssignBrigade(): %w", err)
	}

	ticket, err := s.repo.AssignBrigade(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: AssignBrigade(): %w", err)
	}

	return &models.AssignBrigadeResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) CancelTicket(ctx context.Context, in *models.CancelTicketInput) (*models.CancelTicketResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: CancelTicket(): validate: %w", err)
	}

	currentTicket, err := s.repo.GetTicketByID(ctx, in.TicketID)
	if err != nil {
		return nil, fmt.Errorf("service: CancelTicket(): get ticket: %w", err)
	}

	if err = validateStatusTransition(currentTicket.Status, models.TicketStatusCanceled); err != nil {
		return nil, fmt.Errorf("service: CancelTicket(): %w", err)
	}

	ticket, err := s.repo.CancelTicket(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: CancelTicket(): %w", err)
	}

	return &models.CancelTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) CompleteTicket(ctx context.Context, in *models.CompleteTicketInput) (*models.CompleteTicketResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: CompleteTicket(): validate: %w", err)
	}

	currentTicket, err := s.repo.GetTicketByID(ctx, in.TicketID)
	if err != nil {
		return nil, fmt.Errorf("service: CompleteTicket(): get ticket: %w", err)
	}

	if err = validateStatusTransition(currentTicket.Status, models.TicketStatusDone); err != nil {
		return nil, fmt.Errorf("service: CompleteTicket(): %w", err)
	}

	ticket, err := s.repo.CompleteTicket(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: CompleteTicket(): %w", err)
	}

	return &models.CompleteTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) GetTicketStatusHistory(ctx context.Context, in *models.GetTicketStatusHistoryInput) (*models.GetTicketStatusHistoryResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: GetTicketStatusHistory(): validate: %w", err)
	}

	history, total, err := s.repo.GetTicketStatusHistory(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("service: GetTicketStatusHistory(): %w", err)
	}

	return &models.GetTicketStatusHistoryResult{
		History: history,
		Total:   total,
	}, nil
}

func validateStatusTransition(from models.TicketStatus, to models.TicketStatus) error {
	if from == to {
		return errors.New("new status must be different from current status")
	}

	if from == models.TicketStatusDone {
		return errors.New("ticket is already done")
	}

	if from == models.TicketStatusCanceled {
		return errors.New("ticket is already canceled")
	}

	allowedTransitions := map[models.TicketStatus][]models.TicketStatus{
		models.TicketStatusNew: {
			models.TicketStatusAssigned,
			models.TicketStatusCanceled,
		},
		models.TicketStatusAssigned: {
			models.TicketStatusInProgress,
			models.TicketStatusCanceled,
		},
		models.TicketStatusInProgress: {
			models.TicketStatusDone,
			models.TicketStatusCanceled,
		},
	}

	nextStatuses, ok := allowedTransitions[from]
	if !ok {
		return errors.New("invalid current status")
	}

	for _, allowedStatus := range nextStatuses {
		if allowedStatus == to {
			return nil
		}
	}

	return fmt.Errorf("invalid status transition: %s -> %s", from, to)
}
