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
	case "CANCELED", "CANCELLED":
		return ticketv1.TicketStatus_TICKET_STATUS_CANCELED
	default:
		return ticketv1.TicketStatus_TICKET_STATUS_UNSPECIFIED
	}
}

func ToProtoPriority(priority string) ticketv1.TicketPriority {
	priorityModel := models.TicketPriority(strings.ToUpper(priority))

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

func ToProtoSortBy(sortBy string) ticketv1.TicketSortBy {
	switch strings.ToLower(sortBy) {
	case "created_at":
		return ticketv1.TicketSortBy_TICKET_SORT_BY_CREATED_AT
	case "updated_at":
		return ticketv1.TicketSortBy_TICKET_SORT_BY_UPDATED_AT
	case "priority":
		return ticketv1.TicketSortBy_TICKET_SORT_BY_PRIORITY
	case "status":
		return ticketv1.TicketSortBy_TICKET_SORT_BY_STATUS
	default:
		return ticketv1.TicketSortBy_TICKET_SORT_BY_UNSPECIFIED
	}
}

func ToProtoSortOrder(sortOrder string) ticketv1.SortOrder {
	switch strings.ToLower(sortOrder) {
	case "asc":
		return ticketv1.SortOrder_SORT_ORDER_ASC
	case "desc":
		return ticketv1.SortOrder_SORT_ORDER_DESC
	default:
		return ticketv1.SortOrder_SORT_ORDER_UNSPECIFIED
	}
}

func ToProtoTimestamp(value string) (*timestamppb.Timestamp, error) {
	if value == "" {
		return nil, nil
	}

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, err
	}

	return timestamppb.New(parsed), nil
}

func FromProtoTicket(t *ticketv1.Ticket) *models.Ticket {
	if t == nil {
		return nil
	}

	return &models.Ticket{
		ID:              t.GetId(),
		DepartmentID:    t.GetDepartmentId(),
		CategoryID:      t.GetCategoryId(),
		UserID:          t.GetUserId(),
		BrigadeID:       t.GetBrigadeId(),
		Title:           t.GetTitle(),
		Description:     t.GetDescription(),
		Status:          FromProtoStatus(t.GetStatus()),
		Priority:        FromProtoPriority(t.GetPriority()),
		Address:         t.GetAddress(),
		Latitude:        t.GetLatitude(),
		Longitude:       t.GetLongitude(),
		CreatedAtUnix:   timestampUnix(t.GetCreatedAt()),
		UpdatedAtUnix:   timestampUnix(t.GetUpdatedAt()),
		AssignedAtUnix:  timestampUnix(t.GetAssignedAt()),
		CompletedAtUnix: timestampUnix(t.GetCompletedAt()),
		CanceledAtUnix:  timestampUnix(t.GetCanceledAt()),
	}
}

func FromProtoCategory(category *ticketv1.TicketCategory) *models.TicketCategory {
	if category == nil {
		return nil
	}

	return &models.TicketCategory{
		ID:            category.GetId(),
		Code:          category.GetCode(),
		Name:          category.GetName(),
		Description:   category.GetDescription(),
		IsActive:      category.GetIsActive(),
		CreatedAtUnix: timestampUnix(category.GetCreatedAt()),
		UpdatedAtUnix: timestampUnix(category.GetUpdatedAt()),
	}
}

func FromProtoStatusHistory(history *ticketv1.TicketStatusHistory) *models.TicketStatusHistory {
	if history == nil {
		return nil
	}

	return &models.TicketStatusHistory{
		ID:            history.GetId(),
		TicketID:      history.GetTicketId(),
		OldStatus:     FromProtoStatus(history.GetOldStatus()),
		NewStatus:     FromProtoStatus(history.GetNewStatus()),
		ChangedBy:     history.GetChangedBy(),
		Comment:       history.GetComment(),
		CreatedAtUnix: timestampUnix(history.GetCreatedAt()),
	}
}

func FromProtoStatus(status ticketv1.TicketStatus) string {
	switch status {
	case ticketv1.TicketStatus_TICKET_STATUS_NEW:
		return string(models.TicketStatusNew)
	case ticketv1.TicketStatus_TICKET_STATUS_ASSIGNED:
		return string(models.TicketStatusAssigned)
	case ticketv1.TicketStatus_TICKET_STATUS_IN_PROGRESS:
		return string(models.TicketStatusInProgress)
	case ticketv1.TicketStatus_TICKET_STATUS_DONE:
		return string(models.TicketStatusDone)
	case ticketv1.TicketStatus_TICKET_STATUS_CANCELED:
		return string(models.TicketStatusCanceled)
	default:
		return ""
	}
}

func FromProtoPriority(priority ticketv1.TicketPriority) string {
	switch priority {
	case ticketv1.TicketPriority_TICKET_PRIORITY_LOW:
		return string(models.TicketPriorityLow)
	case ticketv1.TicketPriority_TICKET_PRIORITY_MEDIUM:
		return string(models.TicketPriorityMedium)
	case ticketv1.TicketPriority_TICKET_PRIORITY_HIGH:
		return string(models.TicketPriorityHigh)
	case ticketv1.TicketPriority_TICKET_PRIORITY_EMERGENCY:
		return string(models.TicketPriorityEmergency)
	default:
		return ""
	}
}

func timestampUnix(ts *timestamppb.Timestamp) int64 {
	if ts == nil {
		return 0
	}

	return ts.AsTime().Unix()
}
