package handler

import (
	"context"
	"fmt"

	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/google/uuid"

	"ticket/models"
	"ticket/src/core/service"
)

type TicketHandler struct {
	ticketv1.UnimplementedTicketServiceServer
	service *service.Service
}

func NewTicketHandler(service *service.Service) *TicketHandler {
	return &TicketHandler{service: service}
}

func (t *TicketHandler) CreateTicket(ctx context.Context, req *ticketv1.CreateTicketRequest) (*ticketv1.CreateTicketResponse, error) {
	departmentID, err := uuid.Parse(req.GetDepartmentId())
	if err != nil {
		return nil, fmt.Errorf("handler: CreateTicket(): invalid department_id: %w", err)
	}

	categoryID, err := uuid.Parse(req.GetCategoryId())
	if err != nil {
		return nil, fmt.Errorf("handler: CreateTicket(): invalid category_id: %w", err)
	}

	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, fmt.Errorf("handler: CreateTicket(): invalid user_id: %w", err)
	}

	in := &models.CreateTicketInput{
		DepartmentID: departmentID,
		CategoryID:   categoryID,
		UserID:       userID,
		Title:        req.GetTitle(),
		Description:  req.GetDescription(),
		Priority:     FromProtoPriority(req.GetPriority()),
		Address:      req.GetAddress(),
		Latitude:     req.GetLatitude(),
		Longitude:    req.GetLongitude(),
	}

	res, err := t.service.CreateTicket(ctx, in)
	if err != nil {
		return nil, err
	}

	return &ticketv1.CreateTicketResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) GetTicket(ctx context.Context, req *ticketv1.GetTicketRequest) (*ticketv1.GetTicketResponse, error) {
	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		return nil, fmt.Errorf("handler: GetTicket(): invalid ticket_id: %w", err)
	}

	in := &models.GetTicketInput{
		TicketID: ticketID,
	}

	res, err := t.service.GetTicket(ctx, in)
	if err != nil {
		return nil, err
	}

	return &ticketv1.GetTicketResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) ListTickets(ctx context.Context, req *ticketv1.ListTicketsRequest) (*ticketv1.ListTicketsResponse, error) {
	departmentID, err := parseOptionalUUID(req.GetDepartmentId(), "department_id")
	if err != nil {
		return nil, fmt.Errorf("handler: ListTickets(): %w", err)
	}

	userID, err := parseOptionalUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, fmt.Errorf("handler: ListTickets(): %w", err)
	}

	brigadeID, err := parseOptionalUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		return nil, fmt.Errorf("handler: ListTickets(): %w", err)
	}

	categoryID, err := parseOptionalUUID(req.GetCategoryId(), "category_id")
	if err != nil {
		return nil, fmt.Errorf("handler: ListTickets(): %w", err)
	}

	var status *models.TicketStatus
	if req.GetStatus() != ticketv1.TicketStatus_TICKET_STATUS_UNSPECIFIED {
		v := FromProtoStatus(req.GetStatus())
		status = &v
	}

	var priority *models.TicketPriority
	if req.GetPriority() != ticketv1.TicketPriority_TICKET_PRIORITY_UNSPECIFIED {
		v := FromProtoPriority(req.GetPriority())
		priority = &v
	}

	in := &models.ListTicketsInput{
		DepartmentID: departmentID,
		UserID:       userID,
		BrigadeID:    brigadeID,
		CategoryID:   categoryID,

		Status:   status,
		Priority: priority,

		CreatedFrom: FromProtoTimestamp(req.GetCreatedFrom()),
		CreatedTo:   FromProtoTimestamp(req.GetCreatedTo()),

		Limit:  req.GetLimit(),
		Offset: req.GetOffset(),

		SortBy:    FromProtoSortBy(req.GetSortBy()),
		SortOrder: FromProtoSortOrder(req.GetSortOrder()),
	}

	res, err := t.service.ListTickets(ctx, in)
	if err != nil {
		return nil, err
	}

	tickets := make([]*ticketv1.Ticket, 0, len(res.Tickets))
	for _, ticket := range res.Tickets {
		tickets = append(tickets, ToProtoTicket(ticket))
	}

	return &ticketv1.ListTicketsResponse{
		Tickets: tickets,
		Total:   res.Total,
	}, nil
}

func (t *TicketHandler) UpdateTicket(ctx context.Context, req *ticketv1.UpdateTicketRequest) (*ticketv1.UpdateTicketResponse, error) {
	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		return nil, fmt.Errorf("handler: UpdateTicket(): invalid ticket_id: %w", err)
	}

	categoryID, err := parseOptionalUUID(req.GetCategoryId(), "category_id")
	if err != nil {
		return nil, fmt.Errorf("handler: UpdateTicket(): %w", err)
	}

	updatedBy, err := parseOptionalUUID(req.GetUpdatedBy(), "updated_by")
	if err != nil {
		return nil, fmt.Errorf("handler: UpdateTicket(): %w", err)
	}

	var priority *models.TicketPriority
	if req.GetPriority() != ticketv1.TicketPriority_TICKET_PRIORITY_UNSPECIFIED {
		v := FromProtoPriority(req.GetPriority())
		priority = &v
	}

	in := &models.UpdateTicketInput{
		TicketID:    ticketID,
		Title:       optionalString(req.GetTitle()),
		Description: optionalString(req.GetDescription()),
		CategoryID:  categoryID,
		Priority:    priority,
		Address:     optionalString(req.GetAddress()),
		UpdatedBy:   updatedBy,
	}

	if req.Latitude != nil {
		lat := req.GetLatitude()
		in.Latitude = &lat
	}

	if req.Longitude != nil {
		lon := req.GetLongitude()
		in.Longitude = &lon
	}

	res, err := t.service.UpdateTicket(ctx, in)
	if err != nil {
		return nil, err
	}

	return &ticketv1.UpdateTicketResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) ChangeTicketStatus(ctx context.Context, req *ticketv1.ChangeTicketStatusRequest) (*ticketv1.ChangeTicketStatusResponse, error) {
	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		return nil, fmt.Errorf("handler: ChangeTicketStatus(): invalid ticket_id: %w", err)
	}

	changedBy, err := uuid.Parse(req.GetChangedBy())
	if err != nil {
		return nil, fmt.Errorf("handler: ChangeTicketStatus(): invalid changed_by: %w", err)
	}

	in := &models.ChangeTicketStatusInput{
		TicketID:  ticketID,
		NewStatus: FromProtoStatus(req.GetNewStatus()),
		ChangedBy: changedBy,
		Comment:   optionalString(req.GetComment()),
	}

	res, err := t.service.ChangeTicketStatus(ctx, in)
	if err != nil {
		return nil, err
	}

	return &ticketv1.ChangeTicketStatusResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) AssignBrigade(ctx context.Context, req *ticketv1.AssignBrigadeRequest) (*ticketv1.AssignBrigadeResponse, error) {
	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		return nil, fmt.Errorf("handler: AssignBrigade(): invalid ticket_id: %w", err)
	}

	brigadeID, err := uuid.Parse(req.GetBrigadeId())
	if err != nil {
		return nil, fmt.Errorf("handler: AssignBrigade(): invalid brigade_id: %w", err)
	}

	assignedBy, err := uuid.Parse(req.GetAssignedBy())
	if err != nil {
		return nil, fmt.Errorf("handler: AssignBrigade(): invalid assigned_by: %w", err)
	}

	in := &models.AssignBrigadeInput{
		TicketID:   ticketID,
		BrigadeID:  brigadeID,
		AssignedBy: assignedBy,
		Comment:    optionalString(req.GetComment()),
	}

	res, err := t.service.AssignBrigade(ctx, in)
	if err != nil {
		return nil, err
	}

	return &ticketv1.AssignBrigadeResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) CancelTicket(ctx context.Context, req *ticketv1.CancelTicketRequest) (*ticketv1.CancelTicketResponse, error) {
	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		return nil, fmt.Errorf("handler: CancelTicket(): invalid ticket_id: %w", err)
	}

	canceledBy, err := uuid.Parse(req.GetCanceledBy())
	if err != nil {
		return nil, fmt.Errorf("handler: CancelTicket(): invalid canceled_by: %w", err)
	}

	in := &models.CancelTicketInput{
		TicketID:   ticketID,
		CanceledBy: canceledBy,
		Reason:     req.GetReason(),
	}

	res, err := t.service.CancelTicket(ctx, in)
	if err != nil {
		return nil, err
	}

	return &ticketv1.CancelTicketResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) CompleteTicket(ctx context.Context, req *ticketv1.CompleteTicketRequest) (*ticketv1.CompleteTicketResponse, error) {
	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		return nil, fmt.Errorf("handler: CompleteTicket(): invalid ticket_id: %w", err)
	}

	completedBy, err := uuid.Parse(req.GetCompletedBy())
	if err != nil {
		return nil, fmt.Errorf("handler: CompleteTicket(): invalid completed_by: %w", err)
	}

	in := &models.CompleteTicketInput{
		TicketID:    ticketID,
		CompletedBy: completedBy,
		Comment:     optionalString(req.GetComment()),
	}

	res, err := t.service.CompleteTicket(ctx, in)
	if err != nil {
		return nil, err
	}

	return &ticketv1.CompleteTicketResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) GetTicketStatusHistory(ctx context.Context, req *ticketv1.GetTicketStatusHistoryRequest) (*ticketv1.GetTicketStatusHistoryResponse, error) {
	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		return nil, fmt.Errorf("handler: GetTicketStatusHistory(): invalid ticket_id: %w", err)
	}

	in := &models.GetTicketStatusHistoryInput{
		TicketID: ticketID,
		Limit:    req.GetLimit(),
		Offset:   req.GetOffset(),
	}

	res, err := t.service.GetTicketStatusHistory(ctx, in)
	if err != nil {
		return nil, err
	}

	history := make([]*ticketv1.TicketStatusHistory, 0, len(res.History))
	for _, item := range res.History {
		history = append(history, toProtoStatusHistory(item))
	}

	return &ticketv1.GetTicketStatusHistoryResponse{
		History: history,
		Total:   res.Total,
	}, nil
}

func (t *TicketHandler) CreateCategory(ctx context.Context, req *ticketv1.CreateCategoryRequest) (*ticketv1.CreateCategoryResponse, error) {
	in := &models.CreateCategoryInput{
		Code:        req.GetCode(),
		Name:        req.GetName(),
		Description: optionalString(req.GetDescription()),
	}

	res, err := t.service.CreateCategory(ctx, in)
	if err != nil {
		return nil, err
	}

	return &ticketv1.CreateCategoryResponse{
		Category: toProtoCategory(res.Category),
	}, nil
}

func (t *TicketHandler) GetCategory(ctx context.Context, req *ticketv1.GetCategoryRequest) (*ticketv1.GetCategoryResponse, error) {
	categoryID, err := uuid.Parse(req.GetCategoryId())
	if err != nil {
		return nil, fmt.Errorf("handler: GetCategory(): invalid category_id: %w", err)
	}

	in := &models.GetCategoryInput{
		CategoryID: categoryID,
	}

	res, err := t.service.GetCategory(ctx, in)
	if err != nil {
		return nil, err
	}

	return &ticketv1.GetCategoryResponse{
		Category: toProtoCategory(res.Category),
	}, nil
}

func (t *TicketHandler) ListCategories(ctx context.Context, req *ticketv1.ListCategoriesRequest) (*ticketv1.ListCategoriesResponse, error) {
	in := &models.ListCategoriesInput{
		OnlyActive: req.GetOnlyActive(),
		Limit:      req.GetLimit(),
		Offset:     req.GetOffset(),
	}

	res, err := t.service.ListCategories(ctx, in)
	if err != nil {
		return nil, err
	}

	categories := make([]*ticketv1.TicketCategory, 0, len(res.Categories))
	for _, category := range res.Categories {
		categories = append(categories, toProtoCategory(category))
	}

	return &ticketv1.ListCategoriesResponse{
		Categories: categories,
		Total:      res.Total,
	}, nil
}

func (t *TicketHandler) UpdateCategory(ctx context.Context, req *ticketv1.UpdateCategoryRequest) (*ticketv1.UpdateCategoryResponse, error) {
	categoryID, err := uuid.Parse(req.GetCategoryId())
	if err != nil {
		return nil, fmt.Errorf("handler: UpdateCategory(): invalid category_id: %w", err)
	}

	isActive := req.GetIsActive()

	in := &models.UpdateCategoryInput{
		CategoryID:  categoryID,
		Name:        optionalString(req.GetName()),
		Description: optionalString(req.GetDescription()),
		IsActive:    &isActive,
	}

	res, err := t.service.UpdateCategory(ctx, in)
	if err != nil {
		return nil, err
	}

	return &ticketv1.UpdateCategoryResponse{
		Category: toProtoCategory(res.Category),
	}, nil
}

func (t *TicketHandler) DeleteCategory(ctx context.Context, req *ticketv1.DeleteCategoryRequest) (*ticketv1.DeleteCategoryResponse, error) {
	categoryID, err := uuid.Parse(req.GetCategoryId())
	if err != nil {
		return nil, fmt.Errorf("handler: DeleteCategory(): invalid category_id: %w", err)
	}

	in := &models.DeleteCategoryInput{
		CategoryID: categoryID,
	}

	res, err := t.service.DeleteCategory(ctx, in)
	if err != nil {
		return nil, err
	}

	return &ticketv1.DeleteCategoryResponse{
		Category: toProtoCategory(res.Category),
	}, nil
}

func parseOptionalUUID(value string, field string) (*uuid.UUID, error) {
	if value == "" {
		return nil, nil
	}

	parsed, err := uuid.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", field, err)
	}

	return &parsed, nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}

	return &value
}

func toProtoCategory(category *models.TicketCategory) *ticketv1.TicketCategory {
	if category == nil {
		return nil
	}

	return &ticketv1.TicketCategory{
		Id:          category.ID.String(),
		Code:        category.Code,
		Name:        category.Name,
		Description: category.Description,
		IsActive:    category.IsActive,
		CreatedAt:   ToProtoTimestamp(category.CreatedAt),
		UpdatedAt:   ToProtoTimestamp(category.UpdatedAt),
	}
}

func toProtoStatusHistory(item *models.TicketStatusHistory) *ticketv1.TicketStatusHistory {
	if item == nil {
		return nil
	}

	oldStatus := ticketv1.TicketStatus_TICKET_STATUS_UNSPECIFIED
	if item.OldStatus != nil {
		oldStatus = ToProtoStatus(*item.OldStatus)
	}

	changedBy := ""
	if item.ChangedBy != nil {
		changedBy = item.ChangedBy.String()
	}

	comment := ""
	if item.Comment != nil {
		comment = *item.Comment
	}

	return &ticketv1.TicketStatusHistory{
		Id:        item.ID.String(),
		TicketId:  item.TicketID.String(),
		OldStatus: oldStatus,
		NewStatus: ToProtoStatus(item.NewStatus),
		ChangedBy: changedBy,
		Comment:   comment,
		CreatedAt: ToProtoTimestamp(item.CreatedAt),
	}
}
