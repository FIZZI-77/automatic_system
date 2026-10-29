package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"ticket/models"
	"ticket/src/core/repository"
)

type ReportServiceStruct struct {
	tickets repository.TicketRepository
	reports *repository.ReportRepository
}

// NewReportService создаёт службу отчётов и её репозиторий поверх общего хранилища заявок.
func NewReportService(repo *repository.Repository) *ReportServiceStruct {
	return &ReportServiceStruct{tickets: repo.TicketRepository, reports: repository.NewReportRepository(repo)}
}

// CreateWorkReport проверяет входные данные отчёта и передаёт сохранение репозиторию.
// Ошибку валидации оборачивает в ErrValidation.
func (s *ReportServiceStruct) CreateWorkReport(ctx context.Context, in *models.CreateWorkReportInput) (*models.WorkReport, error) {

	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", models.ErrValidation, err)
	}

	return s.reports.Create(ctx, in)
}

// ListWorkReports возвращает отчёты заявки после проверки права чтения её карточки.
// При отсутствии доступа возвращает ErrPermissionDenied.
func (s *ReportServiceStruct) ListWorkReports(ctx context.Context, ticketID, actor uuid.UUID, actorBrigadeID, actorDepartmentID *uuid.UUID, roles []string) ([]*models.WorkReport, error) {
	ticket, err := s.tickets.GetTicketByID(ctx, ticketID)

	if err != nil {
		return nil, err
	}

	if !canReadTicket(ticket, &actor, actorBrigadeID, actorDepartmentID, roles) {
		return nil, models.ErrPermissionDenied
	}

	return s.reports.List(ctx, ticketID)
}
