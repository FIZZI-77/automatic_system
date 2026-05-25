package service

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"ticket/models"
	"ticket/src/core/repository"
)

type TicketServiceStruct struct {
	repo   *repository.Repository
	logger *zap.Logger
}

func NewTicketServiceStruct(repo *repository.Repository, logger *zap.Logger) *TicketServiceStruct {
	return &TicketServiceStruct{
		repo:   repo,
		logger: logger,
	}
}

func (s *TicketServiceStruct) CreateTicket(ctx context.Context, in *models.CreateTicketInput) (*models.CreateTicketResult, error) {
	start := time.Now()

	s.logger.Info("CreateTicket",
		zap.String("user_id", in.UserID.String()),
		zap.String("department_id", in.DepartmentID.String()),
		zap.String("category_id", in.CategoryID.String()),
		zap.String("title", in.Title),
	)

	if err := in.Validate(); err != nil {
		s.logger.Warn("CreateTicket validation failed",
			zap.String("user_id", in.UserID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CreateTicket(): %w: %v", models.ErrValidation, err)
	}

	ticket, err := s.repo.CreateTicket(ctx, in)
	if err != nil {
		s.logger.Error("CreateTicket failed",
			zap.String("user_id", in.UserID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CreateTicket(): %w", err)
	}

	s.logger.Info("CreateTicket success",
		zap.String("ticket_id", ticket.ID.String()),
		zap.String("user_id", in.UserID.String()),
		zap.String("status", string(ticket.Status)),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.CreateTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) GetTicket(ctx context.Context, in *models.GetTicketInput) (*models.GetTicketResult, error) {
	start := time.Now()

	s.logger.Info("GetTicket",
		zap.String("ticket_id", in.TicketID.String()),
	)

	if err := in.Validate(); err != nil {
		s.logger.Warn("GetTicket validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetTicket(): %w: %v", models.ErrValidation, err)
	}

	ticket, err := s.repo.GetTicketByID(ctx, in.TicketID)
	if err != nil {
		s.logger.Error("GetTicket failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetTicket(): %w", err)
	}

	s.logger.Info("GetTicket success",
		zap.String("ticket_id", ticket.ID.String()),
		zap.String("status", string(ticket.Status)),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.GetTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) ListTickets(ctx context.Context, in *models.ListTicketsInput) (*models.ListTicketsResult, error) {
	start := time.Now()

	s.logger.Info("ListTickets",
		zap.Int32("limit", in.Limit),
		zap.Int32("offset", in.Offset),
	)

	if in.DepartmentID != nil {
		s.logger.Debug("ListTickets department_id", zap.String("department_id", in.DepartmentID.String()))
	}
	if in.UserID != nil {
		s.logger.Debug("ListTickets user_id", zap.String("user_id", in.UserID.String()))
	}
	if in.Status != nil {
		s.logger.Debug("ListTickets status", zap.String("status", string(*in.Status)))
	}
	if in.Priority != nil {
		s.logger.Debug("ListTickets priority", zap.String("priority", string(*in.Priority)))
	}

	if err := in.Validate(); err != nil {
		s.logger.Warn("ListTickets validation failed",
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListTickets(): %w: %v", models.ErrValidation, err)
	}

	tickets, total, err := s.repo.ListTickets(ctx, in)
	if err != nil {
		s.logger.Error("ListTickets failed",
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListTickets(): %w", err)
	}

	s.logger.Info("ListTickets success",
		zap.Int("count", len(tickets)),
		zap.Int64("total", total),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.ListTicketsResult{
		Tickets: tickets,
		Total:   total,
	}, nil
}

func (s *TicketServiceStruct) UpdateTicket(ctx context.Context, in *models.UpdateTicketInput) (*models.UpdateTicketResult, error) {
	start := time.Now()

	s.logger.Info("UpdateTicket",
		zap.String("ticket_id", in.TicketID.String()),
	)

	if in.Title != nil {
		s.logger.Debug("UpdateTicket title", zap.String("title", *in.Title))
	}
	if in.Priority != nil {
		s.logger.Debug("UpdateTicket priority", zap.String("priority", string(*in.Priority)))
	}

	if err := in.Validate(); err != nil {
		s.logger.Warn("UpdateTicket validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: UpdateTicket(): %w: %v", models.ErrValidation, err)
	}

	ticket, err := s.repo.UpdateTicket(ctx, in)
	if err != nil {
		s.logger.Error("UpdateTicket failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: UpdateTicket(): %w", err)
	}

	s.logger.Info("UpdateTicket success",
		zap.String("ticket_id", ticket.ID.String()),
		zap.String("status", string(ticket.Status)),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.UpdateTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) ChangeTicketStatus(ctx context.Context, in *models.ChangeTicketStatusInput) (*models.ChangeTicketStatusResult, error) {
	start := time.Now()

	s.logger.Info("ChangeTicketStatus",
		zap.String("ticket_id", in.TicketID.String()),
		zap.String("new_status", string(in.NewStatus)),
		zap.String("changed_by", in.ChangedBy.String()),
	)

	if err := in.Validate(); err != nil {
		s.logger.Warn("ChangeTicketStatus validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ChangeTicketStatus(): %w: %v", models.ErrValidation, err)
	}

	ticket, err := s.repo.ChangeTicketStatus(ctx, in)
	if err != nil {
		s.logger.Error("ChangeTicketStatus failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.String("new_status", string(in.NewStatus)),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ChangeTicketStatus(): %w", err)
	}

	s.logger.Info("ChangeTicketStatus success",
		zap.String("ticket_id", ticket.ID.String()),
		zap.String("new_status", string(ticket.Status)),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.ChangeTicketStatusResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) AssignBrigade(ctx context.Context, in *models.AssignBrigadeInput) (*models.AssignBrigadeResult, error) {
	start := time.Now()

	s.logger.Info("AssignBrigade",
		zap.String("ticket_id", in.TicketID.String()),
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.String("assigned_by", in.AssignedBy.String()),
	)

	if err := in.Validate(); err != nil {
		s.logger.Warn("AssignBrigade validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: AssignBrigade(): %w: %v", models.ErrValidation, err)
	}

	ticket, err := s.repo.AssignBrigade(ctx, in)
	if err != nil {
		s.logger.Error("AssignBrigade failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.String("brigade_id", in.BrigadeID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: AssignBrigade(): %w", err)
	}

	s.logger.Info("AssignBrigade success",
		zap.String("ticket_id", ticket.ID.String()),
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.String("status", string(ticket.Status)),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.AssignBrigadeResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) CancelTicket(ctx context.Context, in *models.CancelTicketInput) (*models.CancelTicketResult, error) {
	start := time.Now()

	s.logger.Info("CancelTicket",
		zap.String("ticket_id", in.TicketID.String()),
		zap.String("canceled_by", in.CanceledBy.String()),
	)

	if err := in.Validate(); err != nil {
		s.logger.Warn("CancelTicket validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CancelTicket(): %w: %v", models.ErrValidation, err)
	}

	ticket, err := s.repo.CancelTicket(ctx, in)
	if err != nil {
		s.logger.Error("CancelTicket failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CancelTicket(): %w", err)
	}

	s.logger.Info("CancelTicket success",
		zap.String("ticket_id", ticket.ID.String()),
		zap.String("status", string(ticket.Status)),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.CancelTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) CompleteTicket(ctx context.Context, in *models.CompleteTicketInput) (*models.CompleteTicketResult, error) {
	start := time.Now()

	s.logger.Info("CompleteTicket",
		zap.String("ticket_id", in.TicketID.String()),
		zap.String("completed_by", in.CompletedBy.String()),
	)

	if err := in.Validate(); err != nil {
		s.logger.Warn("CompleteTicket validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CompleteTicket(): %w: %v", models.ErrValidation, err)
	}

	ticket, err := s.repo.CompleteTicket(ctx, in)
	if err != nil {
		s.logger.Error("CompleteTicket failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CompleteTicket(): %w", err)
	}

	s.logger.Info("CompleteTicket success",
		zap.String("ticket_id", ticket.ID.String()),
		zap.String("status", string(ticket.Status)),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.CompleteTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) GetTicketStatusHistory(ctx context.Context, in *models.GetTicketStatusHistoryInput) (*models.GetTicketStatusHistoryResult, error) {
	start := time.Now()

	s.logger.Info("GetTicketStatusHistory",
		zap.String("ticket_id", in.TicketID.String()),
		zap.Int32("limit", in.Limit),
		zap.Int32("offset", in.Offset),
	)

	if err := in.Validate(); err != nil {
		s.logger.Warn("GetTicketStatusHistory validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetTicketStatusHistory(): %w: %v", models.ErrValidation, err)
	}

	history, total, err := s.repo.GetTicketStatusHistory(ctx, in)
	if err != nil {
		s.logger.Error("GetTicketStatusHistory failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetTicketStatusHistory(): %w", err)
	}

	s.logger.Info("GetTicketStatusHistory success",
		zap.String("ticket_id", in.TicketID.String()),
		zap.Int("count", len(history)),
		zap.Int64("total", total),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.GetTicketStatusHistoryResult{
		History: history,
		Total:   total,
	}, nil
}
