package service

import (
	"context"
	"fmt"

	"ticket/models"
)

// CreateRequest проверяет обращение и передаёт его транзакционное создание репозиторию.
// Результат содержит обращение, связанный инцидент и признак найденного совпадения.
func (s *TicketServiceStruct) CreateRequest(
	ctx context.Context,
	in *models.CreateRequestInput,
) (*models.CreateRequestResult, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: CreateRequest(): %w: %v", models.ErrValidation, err)
	}

	result, err := s.repo.CreateRequest(ctx, in)

	if err != nil {
		return nil, fmt.Errorf("service: CreateRequest(): %w", err)
	}

	return result, nil
}

// AttachRequest присоединяет обращение к инциденту, в том числе другого департамента.
// Требует право управления обращением; для одного департамента также проверяет
// право управления инцидентом. Ошибки проверки данных и доступа возвращает вызывающему.
func (s *TicketServiceStruct) AttachRequest(
	ctx context.Context,
	in *models.AttachRequestInput,
) (*models.Ticket, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: AttachRequest(): %w: %v", models.ErrValidation, err)
	}

	incident, err := s.repo.GetTicketByID(ctx, in.IncidentID)

	if err != nil {
		return nil, fmt.Errorf("service: AttachRequest(): get incident: %w", err)
	}

	request, err := s.repo.GetTicketByID(ctx, in.RequestID)

	if err != nil {
		return nil, fmt.Errorf("service: AttachRequest(): get request: %w", err)
	}

	if !canManageTicket(request, in.ActorDepartmentID, in.ActorRoles) {
		return nil, fmt.Errorf("service: AttachRequest(): %w", models.ErrPermissionDenied)
	}

	if incident.DepartmentID == request.DepartmentID && !canManageTicket(incident, in.ActorDepartmentID, in.ActorRoles) {
		return nil, fmt.Errorf("service: AttachRequest(): %w", models.ErrPermissionDenied)
	}

	request, err = s.repo.AttachRequest(ctx, in)

	if err != nil {
		return nil, fmt.Errorf("service: AttachRequest(): %w", err)
	}

	return request, nil
}

// DetachRequest отсоединяет обращение от инцидента после проверки входа и права управления.
// Изменение связи и обязательную причину передаёт репозиторию.
func (s *TicketServiceStruct) DetachRequest(
	ctx context.Context,
	in *models.DetachRequestInput,
) (*models.Ticket, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("service: DetachRequest(): %w: %v", models.ErrValidation, err)
	}

	request, err := s.repo.GetTicketByID(ctx, in.RequestID)

	if err != nil {
		return nil, fmt.Errorf("service: DetachRequest(): get request: %w", err)
	}

	if !canManageTicket(request, in.ActorDepartmentID, in.ActorRoles) {
		return nil, fmt.Errorf("service: DetachRequest(): %w", models.ErrPermissionDenied)
	}

	request, err = s.repo.DetachRequest(ctx, in)

	if err != nil {
		return nil, fmt.Errorf("service: DetachRequest(): %w", err)
	}

	return request, nil
}

// ListIncidentRequests возвращает страницу частей инцидента и их общее количество.
// Разрешает доступ при праве управления инцидентом, роли admin или наличии части
// департамента исполнителя; иначе возвращает ErrPermissionDenied.
func (s *TicketServiceStruct) ListIncidentRequests(
	ctx context.Context,
	in *models.ListIncidentRequestsInput,
) ([]*models.Ticket, int64, error) {
	if err := in.Validate(); err != nil {
		return nil, 0, fmt.Errorf("service: ListIncidentRequests(): %w: %v", models.ErrValidation, err)
	}

	incident, err := s.repo.GetTicketByID(ctx, in.IncidentID)

	if err != nil {
		return nil, 0, fmt.Errorf("service: ListIncidentRequests(): get incident: %w", err)
	}

	canManageIncident := canManageTicket(incident, in.ActorDepartmentID, in.ActorRoles)
	canManagePart, err := s.repo.IncidentHasDepartment(ctx, in.IncidentID, in.ActorDepartmentID)

	if err != nil {
		return nil, 0, fmt.Errorf("service: ListIncidentRequests(): check department access: %w", err)
	}

	if !canManageIncident && !hasRole(in.ActorRoles, "admin") && !canManagePart {
		return nil, 0, fmt.Errorf("service: ListIncidentRequests(): %w", models.ErrPermissionDenied)
	}

	requests, total, err := s.repo.ListIncidentRequests(ctx, in)

	if err != nil {
		return nil, 0, fmt.Errorf("service: ListIncidentRequests(): %w", err)
	}

	return requests, total, nil
}
