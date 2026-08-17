package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"ticket/models"
	"ticket/src/core/repository"
)

type ReportService struct {
	tickets repository.TicketRepository
	reports *repository.ReportRepository
}

func NewReportService(repo *repository.Repository) *ReportService {
	return &ReportService{tickets: repo.TicketRepository, reports: repository.NewReportRepository(repo)}
}

func (s *ReportService) Create(ctx context.Context, in *models.CreateWorkReportInput) (*models.WorkReport, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", models.ErrValidation, err)
	}
	ticket, err := s.tickets.GetTicketByID(ctx, in.TicketID)
	if err != nil {
		return nil, err
	}
	if ticket.Status != models.TicketStatusInProgress && ticket.Status != models.TicketStatusAssigned {
		return nil, fmt.Errorf("%w: report can only be added to an active ticket", models.ErrInvalidStatusTransition)
	}
	if !hasPrivilegedRole(in.ActorRoles) && (!hasRole(in.ActorRoles, "worker") || in.ActorBrigadeID == nil || ticket.BrigadeID == nil || *ticket.BrigadeID != *in.ActorBrigadeID) {
		return nil, models.ErrPermissionDenied
	}
	return s.reports.Create(ctx, in)
}
func (s *ReportService) List(ctx context.Context, ticketID, actor uuid.UUID, actorBrigadeID *uuid.UUID, roles []string) ([]*models.WorkReport, error) {
	ticket, err := s.tickets.GetTicketByID(ctx, ticketID)
	if err != nil {
		return nil, err
	}
	if !canReadTicket(ticket, &actor, actorBrigadeID, roles) {
		return nil, models.ErrPermissionDenied
	}
	return s.reports.List(ctx, ticketID)
}
