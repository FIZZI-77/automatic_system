package handler

import (
	"context"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
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

func CreateTicket(ctx context.Context, req *ticketv1.CreateTicketRequest) (*ticketv1.CreateTicketResponse, error) {

	in := &models.CreateTicketInput{
		DepartmentID: req.GetDepartmentId(),
		CategoryID:   req.GetCategoryId(),
		UserID:       req.GetUserId(),
		Title:        req.GetTitle(),
		Description:  req.GetDescription(),
		Priority:     FromProtoPriority(req.GetPriority()),
		Address:      req.GetAddress(),
		Latitude:     req.GetLatitude(),
		Longitude:    req.GetLongitude(),
	}

	res, err := service.TicketService.CreateTicket(ctx, in)
	if err != nil {
		return nil, err
	}
}

func FromProtoPriority(pbPriority ticketv1.TicketPriority) models.TicketPriority {
	switch pbPriority {
	case ticketv1.TicketPriority_TICKET_PRIORITY_LOW:
		return models.TicketPriorityLow
	case ticketv1.TicketPriority_TICKET_PRIORITY_MEDIUM:
		return models.TicketPriorityMedium
	case ticketv1.TicketPriority_TICKET_PRIORITY_HIGH:
		return models.TicketPriorityHigh
	case ticketv1.TicketPriority_TICKET_PRIORITY_EMERGENCY:
		return models.TicketPriorityEmergency
	default:
		return models.TicketPriorityLow
	}
}

func ToProtoPriority(tp models.TicketPriority) ticketv1.TicketPriority {
	switch tp {
	case models.TicketPriorityLow:
		return ticketv1.TicketPriority_TICKET_PRIORITY_LOW
	case models.TicketPriorityMedium:
		return ticketv1.TicketPriority_TICKET_PRIORITY_MEDIUM
	case models.TicketPriorityHigh:
		return ticketv1.TicketPriority_TICKET_PRIORITY_HIGH
	case models.TicketPriorityEmergency:
		return ticketv1.TicketPriority_TICKET_PRIORITY_EMERGENCY
	default:
		return ticketv1.TicketPriority_TICKET_PRIORITY_UNSPECIFIED
	}
}
