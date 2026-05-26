package service

import (
	"context"
	"fmt"
	"ticket/pkg"
	"time"

	"github.com/google/uuid"
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
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("CreateTicket",
		zap.String("user_id", in.UserID.String()),
		zap.String("department_id", in.DepartmentID.String()),
		zap.String("category_id", in.CategoryID.String()),
		zap.String("title", in.Title),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("CreateTicket validation failed",
			zap.String("user_id", in.UserID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CreateTicket(): %w: %v", models.ErrValidation, err)
	}

	if !hasPrivilegedRole(in.ActorRoles) {
		if in.ActorUserID == nil || in.UserID != *in.ActorUserID {
			return nil, fmt.Errorf("service: CreateTicket(): %w", models.ErrPermissionDenied)
		}
	}

	ticket, err := s.repo.CreateTicket(ctx, in)
	if err != nil {
		logger.Error("CreateTicket failed",
			zap.String("user_id", in.UserID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CreateTicket(): %w", err)
	}

	logger.Info("CreateTicket success",
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
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("GetTicket",
		zap.String("ticket_id", in.TicketID.String()),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("GetTicket validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetTicket(): %w: %v", models.ErrValidation, err)
	}

	ticket, err := s.repo.GetTicketByID(ctx, in.TicketID)
	if err != nil {
		logger.Error("GetTicket failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetTicket(): %w", err)
	}

	if !canReadTicket(ticket, in.ActorUserID, in.ActorRoles) {
		return nil, fmt.Errorf("service: GetTicket(): %w", models.ErrPermissionDenied)
	}

	logger.Info("GetTicket success",
		zap.String("ticket_id", ticket.ID.String()),
		zap.String("status", string(ticket.Status)),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.GetTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) ListTickets(ctx context.Context, in *models.ListTicketsInput) (*models.ListTicketsResult, error) {
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("ListTickets",
		zap.Int32("limit", in.Limit),
		zap.Int32("offset", in.Offset),
	)

	if in.DepartmentID != nil {
		logger.Debug("ListTickets department_id", zap.String("department_id", in.DepartmentID.String()))
	}
	if in.UserID != nil {
		logger.Debug("ListTickets user_id", zap.String("user_id", in.UserID.String()))
	}
	if in.Status != nil {
		logger.Debug("ListTickets status", zap.String("status", string(*in.Status)))
	}
	if in.Priority != nil {
		logger.Debug("ListTickets priority", zap.String("priority", string(*in.Priority)))
	}

	if !hasPrivilegedRole(in.ActorRoles) {
		if in.ActorUserID == nil {
			return nil, fmt.Errorf("service: ListTickets(): %w", models.ErrPermissionDenied)
		}

		in.UserID = in.ActorUserID
		in.BrigadeID = nil
	}

	if err := in.Validate(); err != nil {
		logger.Warn("ListTickets validation failed",
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListTickets(): %w: %v", models.ErrValidation, err)
	}

	tickets, total, err := s.repo.ListTickets(ctx, in)
	if err != nil {
		logger.Error("ListTickets failed",
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ListTickets(): %w", err)
	}

	logger.Info("ListTickets success",
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
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("UpdateTicket",
		zap.String("ticket_id", in.TicketID.String()),
	)

	if in.Title != nil {
		logger.Debug("UpdateTicket title", zap.String("title", *in.Title))
	}
	if in.Priority != nil {
		logger.Debug("UpdateTicket priority", zap.String("priority", string(*in.Priority)))
	}

	if err := in.Validate(); err != nil {
		logger.Warn("UpdateTicket validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: UpdateTicket(): %w: %v", models.ErrValidation, err)
	}

	ticket, err := s.repo.UpdateTicket(ctx, in)
	if err != nil {
		logger.Error("UpdateTicket failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: UpdateTicket(): %w", err)
	}

	logger.Info("UpdateTicket success",
		zap.String("ticket_id", ticket.ID.String()),
		zap.String("status", string(ticket.Status)),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.UpdateTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) ChangeTicketStatus(ctx context.Context, in *models.ChangeTicketStatusInput) (*models.ChangeTicketStatusResult, error) {
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("ChangeTicketStatus",
		zap.String("ticket_id", in.TicketID.String()),
		zap.String("new_status", string(in.NewStatus)),
		zap.String("changed_by", in.ChangedBy.String()),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("ChangeTicketStatus validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ChangeTicketStatus(): %w: %v", models.ErrValidation, err)
	}

	if !hasPrivilegedRole(in.ActorRoles) {
		return nil, fmt.Errorf("service: ChangeTicketStatus(): %w", models.ErrPermissionDenied)
	}

	ticket, err := s.repo.ChangeTicketStatus(ctx, in)
	if err != nil {
		logger.Error("ChangeTicketStatus failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.String("new_status", string(in.NewStatus)),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: ChangeTicketStatus(): %w", err)
	}

	logger.Info("ChangeTicketStatus success",
		zap.String("ticket_id", ticket.ID.String()),
		zap.String("new_status", string(ticket.Status)),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.ChangeTicketStatusResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) AssignBrigade(ctx context.Context, in *models.AssignBrigadeInput) (*models.AssignBrigadeResult, error) {
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("AssignBrigade",
		zap.String("ticket_id", in.TicketID.String()),
		zap.String("brigade_id", in.BrigadeID.String()),
		zap.String("assigned_by", in.AssignedBy.String()),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("AssignBrigade validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: AssignBrigade(): %w: %v", models.ErrValidation, err)
	}

	if !hasPrivilegedRole(in.ActorRoles) {
		return nil, fmt.Errorf("service: AssignBrigade(): %w", models.ErrPermissionDenied)
	}

	ticket, err := s.repo.AssignBrigade(ctx, in)
	if err != nil {
		logger.Error("AssignBrigade failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.String("brigade_id", in.BrigadeID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: AssignBrigade(): %w", err)
	}

	logger.Info("AssignBrigade success",
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
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("CancelTicket",
		zap.String("ticket_id", in.TicketID.String()),
		zap.String("canceled_by", in.CanceledBy.String()),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("CancelTicket validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CancelTicket(): %w: %v", models.ErrValidation, err)
	}

	currentTicket, err := s.repo.GetTicketByID(ctx, in.TicketID)
	if err != nil {
		return nil, fmt.Errorf("service: CancelTicket(): get ticket: %w", err)
	}

	if !hasPrivilegedRole(in.ActorRoles) && currentTicket.UserID != in.CanceledBy {
		return nil, fmt.Errorf("service: CancelTicket(): %w", models.ErrPermissionDenied)
	}

	ticket, err := s.repo.CancelTicket(ctx, in)
	if err != nil {
		logger.Error("CancelTicket failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CancelTicket(): %w", err)
	}

	logger.Info("CancelTicket success",
		zap.String("ticket_id", ticket.ID.String()),
		zap.String("status", string(ticket.Status)),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.CancelTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) CompleteTicket(ctx context.Context, in *models.CompleteTicketInput) (*models.CompleteTicketResult, error) {
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("CompleteTicket",
		zap.String("ticket_id", in.TicketID.String()),
		zap.String("completed_by", in.CompletedBy.String()),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("CompleteTicket validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CompleteTicket(): %w: %v", models.ErrValidation, err)
	}

	if !hasPrivilegedRole(in.ActorRoles) {
		return nil, fmt.Errorf("service: CompleteTicket(): %w", models.ErrPermissionDenied)
	}

	ticket, err := s.repo.CompleteTicket(ctx, in)
	if err != nil {
		logger.Error("CompleteTicket failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: CompleteTicket(): %w", err)
	}

	logger.Info("CompleteTicket success",
		zap.String("ticket_id", ticket.ID.String()),
		zap.String("status", string(ticket.Status)),
		zap.Duration("duration", time.Since(start)),
	)

	return &models.CompleteTicketResult{
		Ticket: ticket,
	}, nil
}

func (s *TicketServiceStruct) GetTicketStatusHistory(ctx context.Context, in *models.GetTicketStatusHistoryInput) (*models.GetTicketStatusHistoryResult, error) {
	logger := s.logger.With(pkg.RequestIDField(ctx))
	start := time.Now()

	logger.Info("GetTicketStatusHistory",
		zap.String("ticket_id", in.TicketID.String()),
		zap.Int32("limit", in.Limit),
		zap.Int32("offset", in.Offset),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("GetTicketStatusHistory validation failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetTicketStatusHistory(): %w: %v", models.ErrValidation, err)
	}

	ticket, err := s.repo.GetTicketByID(ctx, in.TicketID)
	if err != nil {
		return nil, fmt.Errorf("service: GetTicketStatusHistory(): get ticket: %w", err)
	}

	if !canReadTicket(ticket, in.ActorUserID, in.ActorRoles) {
		return nil, fmt.Errorf("service: GetTicketStatusHistory(): %w", models.ErrPermissionDenied)
	}

	history, total, err := s.repo.GetTicketStatusHistory(ctx, in)
	if err != nil {
		logger.Error("GetTicketStatusHistory failed",
			zap.String("ticket_id", in.TicketID.String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("service: GetTicketStatusHistory(): %w", err)
	}

	logger.Info("GetTicketStatusHistory success",
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

func canReadTicket(ticket *models.Ticket, actorUserID *uuid.UUID, actorRoles []string) bool {
	if ticket == nil {
		return false
	}

	if hasPrivilegedRole(actorRoles) {
		return true
	}

	return actorUserID != nil && ticket.UserID == *actorUserID
}

func hasPrivilegedRole(roles []string) bool {
	for _, role := range roles {
		switch role {
		case "admin", "dispatcher":
			return true
		}
	}

	return false
}
