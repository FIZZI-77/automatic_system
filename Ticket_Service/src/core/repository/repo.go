package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"ticket/models"
)

type TicketRepository interface {
	CreateTicket(ctx context.Context, in *models.CreateTicketInput) (*models.Ticket, error)
	GetTicketByID(ctx context.Context, ticketID uuid.UUID) (*models.Ticket, error)
	ListTickets(ctx context.Context, in *models.ListTicketsInput) ([]*models.Ticket, int64, error)
	UpdateTicket(ctx context.Context, in *models.UpdateTicketInput) (*models.Ticket, error)

	ChangeTicketStatus(ctx context.Context, in *models.ChangeTicketStatusInput) (*models.Ticket, error)
	AssignBrigade(ctx context.Context, in *models.AssignBrigadeInput) (*models.Ticket, error)
	CancelTicket(ctx context.Context, in *models.CancelTicketInput) (*models.Ticket, error)
	CompleteTicket(ctx context.Context, in *models.CompleteTicketInput) (*models.Ticket, error)

	GetTicketStatusHistory(ctx context.Context, in *models.GetTicketStatusHistoryInput) ([]*models.TicketStatusHistory, int64, error)
}

type CategoryRepository interface {
	CreateCategory(ctx context.Context, in *models.CreateCategoryInput) (*models.TicketCategory, error)
	GetCategoryByID(ctx context.Context, categoryID uuid.UUID) (*models.TicketCategory, error)
	ListCategories(ctx context.Context, in *models.ListCategoriesInput) ([]*models.TicketCategory, int64, error)
	UpdateCategory(ctx context.Context, in *models.UpdateCategoryInput) (*models.TicketCategory, error)
	DeleteCategory(ctx context.Context, in *models.DeleteCategoryInput) (*models.TicketCategory, error)
}

type Repository struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
	TicketRepository
	CategoryRepository
}

func NewRepository(pools DBPools) *Repository {
	if pools.Read == nil {
		pools.Read = pools.Write
	}

	ticketRepo := NewTicketRepository(pools.Write, pools.Read)
	categoryRepo := NewCategoryRepository(pools.Write, pools.Read)

	return &Repository{
		writePool:          pools.Write,
		readPool:           pools.Read,
		TicketRepository:   ticketRepo,
		CategoryRepository: categoryRepo,
	}
}
