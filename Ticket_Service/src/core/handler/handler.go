package handler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	"ticket/models"
	"ticket/src/core/service"
)

type TicketHandler struct {
	ticketv1.UnimplementedTicketServiceServer
	service *service.Service
	logger  *zap.Logger
}

func NewTicketHandler(service *service.Service, logger *zap.Logger) *TicketHandler {
	return &TicketHandler{service: service, logger: logger}
}

func (t *TicketHandler) CreateTicket(ctx context.Context, req *ticketv1.CreateTicketRequest) (*ticketv1.CreateTicketResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "CreateTicket"),
		zap.String("user_id", req.UserId),
		zap.String("department_id", req.DepartmentId),
		zap.String("category_id", req.CategoryId),
	)

	departmentID, err := uuid.Parse(req.GetDepartmentId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "CreateTicket"),
			zap.String("user_id", req.UserId),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("CreateTicket", fmt.Errorf("%w: invalid department_id: %v", models.ErrValidation, err))
	}

	categoryID, err := uuid.Parse(req.GetCategoryId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "CreateTicket"),
			zap.String("user_id", req.UserId),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("CreateTicket", fmt.Errorf("%w: invalid category_id: %v", models.ErrValidation, err))
	}

	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "CreateTicket"),
			zap.String("user_id", req.UserId),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("CreateTicket", fmt.Errorf("%w: invalid user_id: %v", models.ErrValidation, err))
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
		t.logger.Warn("gRPC request failed",
			zap.String("method", "CreateTicket"),
			zap.String("user_id", req.UserId),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("CreateTicket", err)
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "CreateTicket"),
		zap.String("user_id", req.UserId),
		zap.String("ticket_id", res.Ticket.ID.String()),
		zap.Duration("duration", time.Since(start)),
	)

	return &ticketv1.CreateTicketResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) GetTicket(ctx context.Context, req *ticketv1.GetTicketRequest) (*ticketv1.GetTicketResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "GetTicket"),
		zap.String("ticket_id", req.GetTicketId()),
	)

	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "GetTicket"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("GetTicket", fmt.Errorf("%w: invalid ticket_id: %v", models.ErrValidation, err))
	}

	in := &models.GetTicketInput{
		TicketID: ticketID,
	}

	res, err := t.service.GetTicket(ctx, in)
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "GetTicket"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("GetTicket", err)
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "GetTicket"),
		zap.String("ticket_id", req.GetTicketId()),
		zap.String("status", string(res.Ticket.Status)),
		zap.Duration("duration", time.Since(start)),
	)

	return &ticketv1.GetTicketResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) ListTickets(ctx context.Context, req *ticketv1.ListTicketsRequest) (*ticketv1.ListTicketsResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "ListTickets"),
		zap.String("department_id", req.GetDepartmentId()),
		zap.String("user_id", req.GetUserId()),
		zap.String("brigade_id", req.GetBrigadeId()),
		zap.String("category_id", req.GetCategoryId()),
	)

	departmentID, err := parseOptionalUUID(req.GetDepartmentId(), "department_id")
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "ListTickets"),
			zap.String("department_id", req.GetDepartmentId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("ListTickets", fmt.Errorf("%w: %v", models.ErrValidation, err))
	}

	userID, err := parseOptionalUUID(req.GetUserId(), "user_id")
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "ListTickets"),
			zap.String("user_id", req.GetUserId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("ListTickets", fmt.Errorf("%w: %v", models.ErrValidation, err))
	}

	brigadeID, err := parseOptionalUUID(req.GetBrigadeId(), "brigade_id")
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "ListTickets"),
			zap.String("brigade_id", req.GetBrigadeId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("ListTickets", fmt.Errorf("%w: %v", models.ErrValidation, err))
	}

	categoryID, err := parseOptionalUUID(req.GetCategoryId(), "category_id")
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "ListTickets"),
			zap.String("category_id", req.GetCategoryId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("ListTickets", fmt.Errorf("%w: %v", models.ErrValidation, err))
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
		Status:       status,
		Priority:     priority,
		CreatedFrom:  FromProtoTimestamp(req.GetCreatedFrom()),
		CreatedTo:    FromProtoTimestamp(req.GetCreatedTo()),
		Limit:        req.GetLimit(),
		Offset:       req.GetOffset(),
		SortBy:       FromProtoSortBy(req.GetSortBy()),
		SortOrder:    FromProtoSortOrder(req.GetSortOrder()),
	}

	res, err := t.service.ListTickets(ctx, in)
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "ListTickets"),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("ListTickets", err)
	}

	tickets := make([]*ticketv1.Ticket, 0, len(res.Tickets))
	for _, ticket := range res.Tickets {
		tickets = append(tickets, ToProtoTicket(ticket))
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "ListTickets"),
		zap.Int("count", len(tickets)),
		zap.Int64("total", res.Total),
		zap.Duration("duration", time.Since(start)),
	)

	return &ticketv1.ListTicketsResponse{
		Tickets: tickets,
		Total:   res.Total,
	}, nil
}

func (t *TicketHandler) UpdateTicket(ctx context.Context, req *ticketv1.UpdateTicketRequest) (*ticketv1.UpdateTicketResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "UpdateTicket"),
		zap.String("ticket_id", req.GetTicketId()),
		zap.String("updated_by", req.GetUpdatedBy()),
	)

	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "UpdateTicket"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("UpdateTicket", fmt.Errorf("%w: invalid ticket_id: %v", models.ErrValidation, err))
	}

	categoryID, err := parseOptionalUUID(req.GetCategoryId(), "category_id")
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "UpdateTicket"),
			zap.String("category_id", req.GetCategoryId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("UpdateTicket", fmt.Errorf("%w: %v", models.ErrValidation, err))
	}

	updatedBy, err := parseOptionalUUID(req.GetUpdatedBy(), "updated_by")
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "UpdateTicket"),
			zap.String("updated_by", req.GetUpdatedBy()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("UpdateTicket", fmt.Errorf("%w: %v", models.ErrValidation, err))
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
		t.logger.Warn("gRPC request failed",
			zap.String("method", "UpdateTicket"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("UpdateTicket", err)
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "UpdateTicket"),
		zap.String("ticket_id", req.GetTicketId()),
		zap.Duration("duration", time.Since(start)),
	)

	return &ticketv1.UpdateTicketResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) ChangeTicketStatus(ctx context.Context, req *ticketv1.ChangeTicketStatusRequest) (*ticketv1.ChangeTicketStatusResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "ChangeTicketStatus"),
		zap.String("ticket_id", req.GetTicketId()),
		zap.String("new_status", req.GetNewStatus().String()),
		zap.String("changed_by", req.GetChangedBy()),
	)

	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "ChangeTicketStatus"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("ChangeTicketStatus", fmt.Errorf("%w: invalid ticket_id: %v", models.ErrValidation, err))
	}

	changedBy, err := uuid.Parse(req.GetChangedBy())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "ChangeTicketStatus"),
			zap.String("changed_by", req.GetChangedBy()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("ChangeTicketStatus", fmt.Errorf("%w: invalid changed_by: %v", models.ErrValidation, err))
	}

	in := &models.ChangeTicketStatusInput{
		TicketID:  ticketID,
		NewStatus: FromProtoStatus(req.GetNewStatus()),
		ChangedBy: changedBy,
		Comment:   optionalString(req.GetComment()),
	}

	res, err := t.service.ChangeTicketStatus(ctx, in)
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "ChangeTicketStatus"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.String("new_status", req.GetNewStatus().String()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("ChangeTicketStatus", err)
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "ChangeTicketStatus"),
		zap.String("ticket_id", req.GetTicketId()),
		zap.String("new_status", req.GetNewStatus().String()),
		zap.Duration("duration", time.Since(start)),
	)

	return &ticketv1.ChangeTicketStatusResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) AssignBrigade(ctx context.Context, req *ticketv1.AssignBrigadeRequest) (*ticketv1.AssignBrigadeResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "AssignBrigade"),
		zap.String("ticket_id", req.GetTicketId()),
		zap.String("brigade_id", req.GetBrigadeId()),
		zap.String("assigned_by", req.GetAssignedBy()),
	)

	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "AssignBrigade"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("AssignBrigade", fmt.Errorf("%w: invalid ticket_id: %v", models.ErrValidation, err))
	}

	brigadeID, err := uuid.Parse(req.GetBrigadeId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "AssignBrigade"),
			zap.String("brigade_id", req.GetBrigadeId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("AssignBrigade", fmt.Errorf("%w: invalid brigade_id: %v", models.ErrValidation, err))
	}

	assignedBy, err := uuid.Parse(req.GetAssignedBy())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "AssignBrigade"),
			zap.String("assigned_by", req.GetAssignedBy()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("AssignBrigade", fmt.Errorf("%w: invalid assigned_by: %v", models.ErrValidation, err))
	}

	in := &models.AssignBrigadeInput{
		TicketID:   ticketID,
		BrigadeID:  brigadeID,
		AssignedBy: assignedBy,
		Comment:    optionalString(req.GetComment()),
	}

	res, err := t.service.AssignBrigade(ctx, in)
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "AssignBrigade"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.String("brigade_id", req.GetBrigadeId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("AssignBrigade", err)
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "AssignBrigade"),
		zap.String("ticket_id", req.GetTicketId()),
		zap.String("brigade_id", req.GetBrigadeId()),
		zap.Duration("duration", time.Since(start)),
	)

	return &ticketv1.AssignBrigadeResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) CancelTicket(ctx context.Context, req *ticketv1.CancelTicketRequest) (*ticketv1.CancelTicketResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "CancelTicket"),
		zap.String("ticket_id", req.GetTicketId()),
		zap.String("canceled_by", req.GetCanceledBy()),
	)

	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "CancelTicket"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("CancelTicket", fmt.Errorf("%w: invalid ticket_id: %v", models.ErrValidation, err))
	}

	canceledBy, err := uuid.Parse(req.GetCanceledBy())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "CancelTicket"),
			zap.String("canceled_by", req.GetCanceledBy()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("CancelTicket", fmt.Errorf("%w: invalid canceled_by: %v", models.ErrValidation, err))
	}

	in := &models.CancelTicketInput{
		TicketID:   ticketID,
		CanceledBy: canceledBy,
		Reason:     req.GetReason(),
	}

	res, err := t.service.CancelTicket(ctx, in)
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "CancelTicket"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("CancelTicket", err)
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "CancelTicket"),
		zap.String("ticket_id", req.GetTicketId()),
		zap.Duration("duration", time.Since(start)),
	)

	return &ticketv1.CancelTicketResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) CompleteTicket(ctx context.Context, req *ticketv1.CompleteTicketRequest) (*ticketv1.CompleteTicketResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "CompleteTicket"),
		zap.String("ticket_id", req.GetTicketId()),
		zap.String("completed_by", req.GetCompletedBy()),
	)

	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "CompleteTicket"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("CompleteTicket", fmt.Errorf("%w: invalid ticket_id: %v", models.ErrValidation, err))
	}

	completedBy, err := uuid.Parse(req.GetCompletedBy())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "CompleteTicket"),
			zap.String("completed_by", req.GetCompletedBy()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("CompleteTicket", fmt.Errorf("%w: invalid completed_by: %v", models.ErrValidation, err))
	}

	in := &models.CompleteTicketInput{
		TicketID:    ticketID,
		CompletedBy: completedBy,
		Comment:     optionalString(req.GetComment()),
	}

	res, err := t.service.CompleteTicket(ctx, in)
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "CompleteTicket"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("CompleteTicket", err)
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "CompleteTicket"),
		zap.String("ticket_id", req.GetTicketId()),
		zap.Duration("duration", time.Since(start)),
	)

	return &ticketv1.CompleteTicketResponse{
		Ticket: ToProtoTicket(res.Ticket),
	}, nil
}

func (t *TicketHandler) GetTicketStatusHistory(ctx context.Context, req *ticketv1.GetTicketStatusHistoryRequest) (*ticketv1.GetTicketStatusHistoryResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "GetTicketStatusHistory"),
		zap.String("ticket_id", req.GetTicketId()),
	)

	ticketID, err := uuid.Parse(req.GetTicketId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "GetTicketStatusHistory"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("GetTicketStatusHistory", fmt.Errorf("%w: invalid ticket_id: %v", models.ErrValidation, err))
	}

	in := &models.GetTicketStatusHistoryInput{
		TicketID: ticketID,
		Limit:    req.GetLimit(),
		Offset:   req.GetOffset(),
	}

	res, err := t.service.GetTicketStatusHistory(ctx, in)
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "GetTicketStatusHistory"),
			zap.String("ticket_id", req.GetTicketId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("GetTicketStatusHistory", err)
	}

	history := make([]*ticketv1.TicketStatusHistory, 0, len(res.History))
	for _, item := range res.History {
		history = append(history, toProtoStatusHistory(item))
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "GetTicketStatusHistory"),
		zap.String("ticket_id", req.GetTicketId()),
		zap.Int("count", len(history)),
		zap.Int64("total", res.Total),
		zap.Duration("duration", time.Since(start)),
	)

	return &ticketv1.GetTicketStatusHistoryResponse{
		History: history,
		Total:   res.Total,
	}, nil
}

func (t *TicketHandler) CreateCategory(ctx context.Context, req *ticketv1.CreateCategoryRequest) (*ticketv1.CreateCategoryResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "CreateCategory"),
		zap.String("code", req.GetCode()),
		zap.String("name", req.GetName()),
	)

	in := &models.CreateCategoryInput{
		Code:        req.GetCode(),
		Name:        req.GetName(),
		Description: optionalString(req.GetDescription()),
	}

	res, err := t.service.CreateCategory(ctx, in)
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "CreateCategory"),
			zap.String("code", req.GetCode()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("CreateCategory", err)
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "CreateCategory"),
		zap.String("category_id", res.Category.ID.String()),
		zap.String("code", req.GetCode()),
		zap.Duration("duration", time.Since(start)),
	)

	return &ticketv1.CreateCategoryResponse{
		Category: toProtoCategory(res.Category),
	}, nil
}

func (t *TicketHandler) GetCategory(ctx context.Context, req *ticketv1.GetCategoryRequest) (*ticketv1.GetCategoryResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "GetCategory"),
		zap.String("category_id", req.GetCategoryId()),
	)

	categoryID, err := uuid.Parse(req.GetCategoryId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "GetCategory"),
			zap.String("category_id", req.GetCategoryId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("GetCategory", fmt.Errorf("%w: invalid category_id: %v", models.ErrValidation, err))
	}

	in := &models.GetCategoryInput{
		CategoryID: categoryID,
	}

	res, err := t.service.GetCategory(ctx, in)
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "GetCategory"),
			zap.String("category_id", req.GetCategoryId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("GetCategory", err)
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "GetCategory"),
		zap.String("category_id", req.GetCategoryId()),
		zap.String("code", res.Category.Code),
		zap.Duration("duration", time.Since(start)),
	)

	return &ticketv1.GetCategoryResponse{
		Category: toProtoCategory(res.Category),
	}, nil
}

func (t *TicketHandler) ListCategories(ctx context.Context, req *ticketv1.ListCategoriesRequest) (*ticketv1.ListCategoriesResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "ListCategories"),
		zap.Bool("only_active", req.GetOnlyActive()),
	)

	in := &models.ListCategoriesInput{
		OnlyActive: req.GetOnlyActive(),
		Limit:      req.GetLimit(),
		Offset:     req.GetOffset(),
	}

	res, err := t.service.ListCategories(ctx, in)
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "ListCategories"),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("ListCategories", err)
	}

	categories := make([]*ticketv1.TicketCategory, 0, len(res.Categories))
	for _, category := range res.Categories {
		categories = append(categories, toProtoCategory(category))
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "ListCategories"),
		zap.Int("count", len(categories)),
		zap.Int64("total", res.Total),
		zap.Duration("duration", time.Since(start)),
	)

	return &ticketv1.ListCategoriesResponse{
		Categories: categories,
		Total:      res.Total,
	}, nil
}

func (t *TicketHandler) UpdateCategory(ctx context.Context, req *ticketv1.UpdateCategoryRequest) (*ticketv1.UpdateCategoryResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "UpdateCategory"),
		zap.String("category_id", req.GetCategoryId()),
		zap.String("name", req.GetName()),
	)

	categoryID, err := uuid.Parse(req.GetCategoryId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "UpdateCategory"),
			zap.String("category_id", req.GetCategoryId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("UpdateCategory", fmt.Errorf("%w: invalid category_id: %v", models.ErrValidation, err))
	}

	in := &models.UpdateCategoryInput{
		CategoryID:  categoryID,
		Name:        optionalString(req.GetName()),
		Description: optionalString(req.GetDescription()),
	}

	if protoHasField(req, "is_active") {
		isActive := req.GetIsActive()
		in.IsActive = &isActive
	}

	res, err := t.service.UpdateCategory(ctx, in)
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "UpdateCategory"),
			zap.String("category_id", req.GetCategoryId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("UpdateCategory", err)
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "UpdateCategory"),
		zap.String("category_id", req.GetCategoryId()),
		zap.String("code", res.Category.Code),
		zap.Duration("duration", time.Since(start)),
	)

	return &ticketv1.UpdateCategoryResponse{
		Category: toProtoCategory(res.Category),
	}, nil
}

func (t *TicketHandler) DeleteCategory(ctx context.Context, req *ticketv1.DeleteCategoryRequest) (*ticketv1.DeleteCategoryResponse, error) {
	start := time.Now()

	t.logger.Info("gRPC request received",
		zap.String("method", "DeleteCategory"),
		zap.String("category_id", req.GetCategoryId()),
	)

	categoryID, err := uuid.Parse(req.GetCategoryId())
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "DeleteCategory"),
			zap.String("category_id", req.GetCategoryId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("DeleteCategory", fmt.Errorf("%w: invalid category_id: %v", models.ErrValidation, err))
	}

	in := &models.DeleteCategoryInput{
		CategoryID: categoryID,
	}

	res, err := t.service.DeleteCategory(ctx, in)
	if err != nil {
		t.logger.Warn("gRPC request failed",
			zap.String("method", "DeleteCategory"),
			zap.String("category_id", req.GetCategoryId()),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return nil, ticketStatusError("DeleteCategory", err)
	}

	t.logger.Info("gRPC request succeeded",
		zap.String("method", "DeleteCategory"),
		zap.String("category_id", req.GetCategoryId()),
		zap.String("code", res.Category.Code),
		zap.Duration("duration", time.Since(start)),
	)

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

func protoHasField(message interface{ ProtoReflect() protoreflect.Message }, fieldName protoreflect.Name) bool {
	field := message.ProtoReflect().Descriptor().Fields().ByName(fieldName)
	if field == nil {
		return false
	}

	return message.ProtoReflect().Has(field)
}

func ticketStatusError(method string, err error) error {
	return status.Errorf(ticketErrorCode(err), "failed %s: %v", method, err)
}

func ticketErrorCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}

	switch {
	case errors.Is(err, models.ErrValidation):
		return codes.InvalidArgument
	case errors.Is(err, models.ErrNotFound):
		return codes.NotFound
	case errors.Is(err, models.ErrAlreadyExists):
		return codes.AlreadyExists
	case errors.Is(err, models.ErrCategoryInactive),
		errors.Is(err, models.ErrInvalidStatusTransition),
		errors.Is(err, models.ErrTicketTerminalState):
		return codes.FailedPrecondition
	default:
		return codes.Internal
	}
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
