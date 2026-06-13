package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
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
	db           *sql.DB
	ticketRepo   *TicketRepoStruct
	categoryRepo *CategoryRepoStruct
	TicketRepository
	CategoryRepository
}

func NewRepository(db *sql.DB) *Repository {
	ticketRepo := NewTicketRepository(db)
	categoryRepo := NewCategoryRepository(db)

	return &Repository{
		db:                 db,
		ticketRepo:         ticketRepo,
		categoryRepo:       categoryRepo,
		TicketRepository:   ticketRepo,
		CategoryRepository: categoryRepo,
	}
}

func newRepositoryWithExecutor(exec DBTX) *Repository {
	ticketRepo := NewTicketRepository(exec)
	categoryRepo := NewCategoryRepository(exec)

	return &Repository{
		ticketRepo:         ticketRepo,
		categoryRepo:       categoryRepo,
		TicketRepository:   ticketRepo,
		CategoryRepository: categoryRepo,
	}
}

func (r *Repository) WithTx(ctx context.Context, fn func(txRepo *Repository) error) error {
	if r.db == nil {
		return fmt.Errorf("repository: WithTx(): root db is unavailable")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("repository: WithTx(): begin tx: %w", err)
	}
	defer tx.Rollback()

	if err = fn(newRepositoryWithExecutor(tx)); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("repository: WithTx(): commit: %w", err)
	}

	return nil
}

func (r *Repository) CreateTicket(ctx context.Context, in *models.CreateTicketInput) (*models.Ticket, error) {
	if r.db == nil || r.ticketRepo == nil {
		return r.TicketRepository.CreateTicket(ctx, in)
	}

	var ticket *models.Ticket
	err := r.WithTx(ctx, func(txRepo *Repository) error {
		var err error
		ticket, err = txRepo.ticketRepo.createTicket(ctx, in)
		return err
	})
	if err != nil {
		return nil, err
	}

	return ticket, nil
}

func (r *Repository) UpdateTicket(ctx context.Context, in *models.UpdateTicketInput) (*models.Ticket, error) {
	if r.db == nil || r.ticketRepo == nil {
		return r.TicketRepository.UpdateTicket(ctx, in)
	}

	var ticket *models.Ticket
	err := r.WithTx(ctx, func(txRepo *Repository) error {
		var err error
		ticket, err = txRepo.ticketRepo.updateTicket(ctx, in)
		return err
	})
	if err != nil {
		return nil, err
	}

	return ticket, nil
}

func (r *Repository) ChangeTicketStatus(ctx context.Context, in *models.ChangeTicketStatusInput) (*models.Ticket, error) {
	if r.db == nil || r.ticketRepo == nil {
		return r.TicketRepository.ChangeTicketStatus(ctx, in)
	}

	var ticket *models.Ticket
	err := r.WithTx(ctx, func(txRepo *Repository) error {
		var err error
		ticket, err = txRepo.ticketRepo.changeTicketStatus(ctx, in)
		return err
	})
	if err != nil {
		return nil, err
	}

	return ticket, nil
}

func (r *Repository) AssignBrigade(ctx context.Context, in *models.AssignBrigadeInput) (*models.Ticket, error) {
	if r.db == nil || r.ticketRepo == nil {
		return r.TicketRepository.AssignBrigade(ctx, in)
	}

	var ticket *models.Ticket
	err := r.WithTx(ctx, func(txRepo *Repository) error {
		var err error
		ticket, err = txRepo.ticketRepo.assignBrigade(ctx, in)
		return err
	})
	if err != nil {
		return nil, err
	}

	return ticket, nil
}

func (r *Repository) CancelTicket(ctx context.Context, in *models.CancelTicketInput) (*models.Ticket, error) {
	if r.db == nil || r.ticketRepo == nil {
		return r.TicketRepository.CancelTicket(ctx, in)
	}

	var ticket *models.Ticket
	err := r.WithTx(ctx, func(txRepo *Repository) error {
		var err error
		ticket, err = txRepo.ticketRepo.cancelTicket(ctx, in)
		return err
	})
	if err != nil {
		return nil, err
	}

	return ticket, nil
}

func (r *Repository) CompleteTicket(ctx context.Context, in *models.CompleteTicketInput) (*models.Ticket, error) {
	if r.db == nil || r.ticketRepo == nil {
		return r.TicketRepository.CompleteTicket(ctx, in)
	}

	var ticket *models.Ticket
	err := r.WithTx(ctx, func(txRepo *Repository) error {
		var err error
		ticket, err = txRepo.ticketRepo.completeTicket(ctx, in)
		return err
	})
	if err != nil {
		return nil, err
	}

	return ticket, nil
}

func (r *Repository) CreateCategory(ctx context.Context, in *models.CreateCategoryInput) (*models.TicketCategory, error) {
	if r.db == nil || r.categoryRepo == nil {
		return r.CategoryRepository.CreateCategory(ctx, in)
	}

	var category *models.TicketCategory
	err := r.WithTx(ctx, func(txRepo *Repository) error {
		var err error
		category, err = txRepo.categoryRepo.createCategory(ctx, in)
		return err
	})
	if err != nil {
		return nil, err
	}

	return category, nil
}

func (r *Repository) UpdateCategory(ctx context.Context, in *models.UpdateCategoryInput) (*models.TicketCategory, error) {
	if r.db == nil || r.categoryRepo == nil {
		return r.CategoryRepository.UpdateCategory(ctx, in)
	}

	var category *models.TicketCategory
	err := r.WithTx(ctx, func(txRepo *Repository) error {
		var err error
		category, err = txRepo.categoryRepo.updateCategory(ctx, in)
		return err
	})
	if err != nil {
		return nil, err
	}

	return category, nil
}

func (r *Repository) DeleteCategory(ctx context.Context, in *models.DeleteCategoryInput) (*models.TicketCategory, error) {
	if r.db == nil || r.categoryRepo == nil {
		return r.CategoryRepository.DeleteCategory(ctx, in)
	}

	var category *models.TicketCategory
	err := r.WithTx(ctx, func(txRepo *Repository) error {
		var err error
		category, err = txRepo.categoryRepo.deleteCategory(ctx, in)
		return err
	})
	if err != nil {
		return nil, err
	}

	return category, nil
}
