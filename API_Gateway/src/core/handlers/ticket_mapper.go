package handlers

import (
	"gateway/models"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"strings"
	"time"
)

func ToProtoStatus(status string) ticketv1.TicketStatus {

	status = strings.ToUpper(status)

	switch status {
	case "NEW":
		return ticketv1.TicketStatus_TICKET_STATUS_NEW
	case "ASSIGNED":
		return ticketv1.TicketStatus_TICKET_STATUS_ASSIGNED
	case "IN_PROGRESS":
		return ticketv1.TicketStatus_TICKET_STATUS_IN_PROGRESS
	case "DONE":
		return ticketv1.TicketStatus_TICKET_STATUS_DONE
	case "CANCELLED":
		return ticketv1.TicketStatus_TICKET_STATUS_CANCELED
	default:
		return ticketv1.TicketStatus_TICKET_STATUS_UNSPECIFIED
	}
}

func ToProtoPriority(priority string) ticketv1.TicketPriority {
	priorityModel := models.TicketPriority(priority)

	switch priorityModel {
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

func ToProtoTicket(ticket *models.Ticket) *ticketv1.Ticket {
	if ticket == nil {
		return nil
	}

	brigadeID := ""
	if ticket.BrigadeID != "" {
		brigadeID = ticket.BrigadeID
	}

	assignedAt := time.Unix(ticket.AssignedAtUnix, 0)
	completedAt := time.Unix(ticket.CompletedAtUnix, 0)
	canceledAt := time.Unix(ticket.CanceledAtUnix, 0)

	return &ticketv1.Ticket{
		Id:           ticket.ID,
		DepartmentId: ticket.DepartmentID,
		CategoryId:   ticket.CategoryID,

		UserId:    ticket.UserID,
		BrigadeId: brigadeID,

		Title:       ticket.Title,
		Description: ticket.Description,

		Status:   ToProtoStatus(ticket.Status),
		Priority: ToProtoPriority(ticket.Priority),

		Address:   ticket.Address,
		Latitude:  ticket.Latitude,
		Longitude: ticket.Longitude,

		CreatedAt:   ToProtoTimestamp(time.Unix(ticket.CreatedAtUnix, 0)),
		UpdatedAt:   ToProtoTimestamp(time.Unix(ticket.UpdatedAtUnix, 0)),
		AssignedAt:  ToProtoTimestampPtr(&assignedAt),
		CompletedAt: ToProtoTimestampPtr(&completedAt),
		CanceledAt:  ToProtoTimestampPtr(&canceledAt),
	}
}
