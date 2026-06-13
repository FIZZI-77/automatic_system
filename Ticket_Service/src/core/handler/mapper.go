package handler

import (
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"ticket/models"
	"time"
)

func ToProtoStatus(status models.TicketStatus) ticketv1.TicketStatus {
	switch status {
	case models.TicketStatusNew:
		return ticketv1.TicketStatus_TICKET_STATUS_NEW
	case models.TicketStatusAssigned:
		return ticketv1.TicketStatus_TICKET_STATUS_ASSIGNED
	case models.TicketStatusInProgress:
		return ticketv1.TicketStatus_TICKET_STATUS_IN_PROGRESS
	case models.TicketStatusDone:
		return ticketv1.TicketStatus_TICKET_STATUS_DONE
	case models.TicketStatusCanceled:
		return ticketv1.TicketStatus_TICKET_STATUS_CANCELED
	default:
		return ticketv1.TicketStatus_TICKET_STATUS_UNSPECIFIED
	}
}

func FromProtoStatus(status ticketv1.TicketStatus) models.TicketStatus {
	switch status {
	case ticketv1.TicketStatus_TICKET_STATUS_NEW:
		return models.TicketStatusNew
	case ticketv1.TicketStatus_TICKET_STATUS_ASSIGNED:
		return models.TicketStatusAssigned
	case ticketv1.TicketStatus_TICKET_STATUS_IN_PROGRESS:
		return models.TicketStatusInProgress
	case ticketv1.TicketStatus_TICKET_STATUS_DONE:
		return models.TicketStatusDone
	case ticketv1.TicketStatus_TICKET_STATUS_CANCELED:
		return models.TicketStatusCanceled
	default:
		return ""
	}
}

func ToProtoPriority(priority models.TicketPriority) ticketv1.TicketPriority {
	switch priority {
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

func FromProtoPriority(priority ticketv1.TicketPriority) models.TicketPriority {
	switch priority {
	case ticketv1.TicketPriority_TICKET_PRIORITY_LOW:
		return models.TicketPriorityLow
	case ticketv1.TicketPriority_TICKET_PRIORITY_MEDIUM:
		return models.TicketPriorityMedium
	case ticketv1.TicketPriority_TICKET_PRIORITY_HIGH:
		return models.TicketPriorityHigh
	case ticketv1.TicketPriority_TICKET_PRIORITY_EMERGENCY:
		return models.TicketPriorityEmergency
	default:
		return ""
	}
}

func FromProtoSortBy(sortBy ticketv1.TicketSortBy) models.TicketSortBy {
	switch sortBy {
	case ticketv1.TicketSortBy_TICKET_SORT_BY_CREATED_AT:
		return models.TicketSortByCreatedAt
	case ticketv1.TicketSortBy_TICKET_SORT_BY_UPDATED_AT:
		return models.TicketSortByUpdatedAt
	case ticketv1.TicketSortBy_TICKET_SORT_BY_PRIORITY:
		return models.TicketSortByPriority
	case ticketv1.TicketSortBy_TICKET_SORT_BY_STATUS:
		return models.TicketSortByStatus
	default:
		return ""
	}
}

func FromProtoSortOrder(order ticketv1.SortOrder) models.SortOrder {
	switch order {
	case ticketv1.SortOrder_SORT_ORDER_ASC:
		return models.SortOrderAsc
	case ticketv1.SortOrder_SORT_ORDER_DESC:
		return models.SortOrderDesc
	default:
		return ""
	}
}

func ToProtoTimestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}

	return timestamppb.New(t)
}

func ToProtoTimestampPtr(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}

	return timestamppb.New(*t)
}

func FromProtoTimestamp(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}

	t := ts.AsTime()
	return &t
}

func ToProtoTicket(ticket *models.Ticket) *ticketv1.Ticket {
	if ticket == nil {
		return nil
	}

	brigadeID := ""
	if ticket.BrigadeID != nil {
		brigadeID = (*ticket.BrigadeID).String()
	}

	return &ticketv1.Ticket{
		Id:           ticket.ID.String(),
		DepartmentId: ticket.DepartmentID.String(),
		CategoryId:   ticket.CategoryID.String(),

		UserId:    ticket.UserID.String(),
		BrigadeId: brigadeID,

		Title:       ticket.Title,
		Description: ticket.Description,

		Status:   ToProtoStatus(ticket.Status),
		Priority: ToProtoPriority(ticket.Priority),

		Address:   ticket.Address,
		Latitude:  ticket.Latitude,
		Longitude: ticket.Longitude,

		CreatedAt:   ToProtoTimestamp(ticket.CreatedAt),
		UpdatedAt:   ToProtoTimestamp(ticket.UpdatedAt),
		AssignedAt:  ToProtoTimestampPtr(ticket.AssignedAt),
		CompletedAt: ToProtoTimestampPtr(ticket.CompletedAt),
		CanceledAt:  ToProtoTimestampPtr(ticket.CanceledAt),
	}
}
