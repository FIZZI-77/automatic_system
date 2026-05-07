package service

import (
	"context"
	"ticket/models"
	"ticket/src/core/repository"
)

type TicketService interface {
	CreateTicket(ctx context.Context, in models.CreateTicketInput) (*models.CreateTicketResult, error)
	GetTicket(ctx context.Context, in models.GetTicketInput) (*models.GetTicketResult, error)
	ListTickets(ctx context.Context, in models.ListTicketsInput) (*models.ListTicketsResult, error)
	UpdateTicket(ctx context.Context, in models.UpdateTicketInput) (*models.UpdateTicketResult, error)

	ChangeTicketStatus(ctx context.Context, in models.ChangeTicketStatusInput) (*models.ChangeTicketStatusResult, error)
	AssignBrigade(ctx context.Context, in models.AssignBrigadeInput) (*models.AssignBrigadeResult, error)
	CancelTicket(ctx context.Context, in models.CancelTicketInput) (*models.CancelTicketResult, error)
	CompleteTicket(ctx context.Context, in models.CompleteTicketInput) (*models.CompleteTicketResult, error)

	GetTicketStatusHistory(ctx context.Context, in models.GetTicketStatusHistoryInput) (*models.GetTicketStatusHistoryResult, error)
}

type CategoryService interface {
	CreateCategory(ctx context.Context, in models.CreateCategoryInput) (*models.CreateCategoryResult, error)
	GetCategory(ctx context.Context, in models.GetCategoryInput) (*models.GetCategoryResult, error)
	ListCategories(ctx context.Context, in models.ListCategoriesInput) (*models.ListCategoriesResult, error)
	UpdateCategory(ctx context.Context, in models.UpdateCategoryInput) (*models.UpdateCategoryResult, error)
	DeleteCategory(ctx context.Context, in models.DeleteCategoryInput) (*models.DeleteCategoryResult, error)
}

type Service struct {
	TicketService
	CategoryService
}

func NewService(repo *repository.Repository) *Service {
	return &Service{
		TicketService:   NewTicketServiceStruct(repo),
		CategoryService: NewCategoryServiceStruct(repo),
	}
}
