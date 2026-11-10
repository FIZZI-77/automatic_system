package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"ticket/models"
)

type TicketRepository interface {
	// CreateTicket сохраняет заявку NEW в активной категории вместе с историей и событием outbox.
	CreateTicket(ctx context.Context, in *models.CreateTicketInput) (*models.Ticket, error)
	// GetTicketByID возвращает неархивную заявку со связями либо ошибку ErrNotFound.
	GetTicketByID(ctx context.Context, ticketID uuid.UUID) (*models.Ticket, error)
	// ListTickets возвращает страницу неархивных заявок по фильтрам и общее количество совпадений.
	ListTickets(ctx context.Context, in *models.ListTicketsInput) ([]*models.Ticket, int64, error)
	// UpdateTicket изменяет переданные поля нетерминальной заявки с проверкой прав и записью outbox.
	UpdateTicket(ctx context.Context, in *models.UpdateTicketInput) (*models.Ticket, error)

	// ChangeTicketStatus применяет допустимый переход, сохраняя историю, outbox и согласованность инцидента.
	ChangeTicketStatus(ctx context.Context, in *models.ChangeTicketStatusInput) (*models.Ticket, error)
	// AssignBrigade назначает свободную бригаду, переводит заявку в ASSIGNED и сохраняет историю и outbox.
	AssignBrigade(ctx context.Context, in *models.AssignBrigadeInput) (*models.Ticket, error)
	// CancelTicket отменяет заявку с причиной, историей и outbox; части инцидента должны быть выполнены.
	CancelTicket(ctx context.Context, in *models.CancelTicketInput) (*models.Ticket, error)
	// CompleteTicket завершает заявку с историей и outbox, проверяя и пересчитывая состояние инцидента.
	CompleteTicket(ctx context.Context, in *models.CompleteTicketInput) (*models.Ticket, error)
	// SubmitTicketFeedback сохраняет оценку выполненной заявки её автором вместе с событием outbox.
	SubmitTicketFeedback(ctx context.Context, in *models.SubmitTicketFeedbackInput) (*models.TicketFeedback, error)
	// GetTicketFeedback возвращает отзыв по заявке либо ErrNotFound при его отсутствии.
	GetTicketFeedback(ctx context.Context, in *models.GetTicketFeedbackInput) (*models.TicketFeedback, error)

	// GetTicketStatusHistory возвращает страницу переходов от старых к новым и их общее количество.
	GetTicketStatusHistory(ctx context.Context, in *models.GetTicketStatusHistoryInput) ([]*models.TicketStatusHistory, int64, error)
}

type RequestRepository interface {
	// CreateRequest сохраняет обращение и связывает его с найденным дубликатом инцидента или новым инцидентом.
	// Повтор внешнего идентификатора возвращает существующую пару.
	CreateRequest(ctx context.Context, in *models.CreateRequestInput) (*models.CreateRequestResult, error)
	// AttachRequest связывает обращение с нетерминальным инцидентом, записывает событие и пересчитывает инциденты.
	AttachRequest(ctx context.Context, in *models.AttachRequestInput) (*models.Ticket, error)
	// DetachRequest снимает связь с инцидентом, записывает событие и пересчитывает завершение прежнего инцидента.
	DetachRequest(ctx context.Context, in *models.DetachRequestInput) (*models.Ticket, error)
	// ListIncidentRequests возвращает страницу неархивных обращений от новых к старым и общий счётчик.
	// На пустой странице общий счётчик равен нулю.
	ListIncidentRequests(ctx context.Context, in *models.ListIncidentRequestsInput) ([]*models.Ticket, int64, error)
	// IncidentHasDepartment проверяет наличие неархивного обращения ведомства; nil departmentID даёт false.
	IncidentHasDepartment(ctx context.Context, incidentID uuid.UUID, departmentID *uuid.UUID) (bool, error)
}

type CategoryRepository interface {
	// CreateCategory сохраняет активную категорию и событие outbox; дубликат даёт ErrAlreadyExists.
	CreateCategory(ctx context.Context, in *models.CreateCategoryInput) (*models.TicketCategory, error)
	// GetCategoryByID возвращает категорию, включая неактивную, либо ErrNotFound.
	GetCategoryByID(ctx context.Context, categoryID uuid.UUID) (*models.TicketCategory, error)
	// ListCategories возвращает категории по имени с пагинацией, фильтром активности и общим счётчиком.
	ListCategories(ctx context.Context, in *models.ListCategoriesInput) ([]*models.TicketCategory, int64, error)
	// UpdateCategory изменяет непустые имя и описание, заданную активность и сохраняет событие outbox.
	UpdateCategory(ctx context.Context, in *models.UpdateCategoryInput) (*models.TicketCategory, error)
	// DeleteCategory деактивирует категорию, сохраняет событие outbox и возвращает обновлённую запись.
	DeleteCategory(ctx context.Context, in *models.DeleteCategoryInput) (*models.TicketCategory, error)
}

type Repository struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
	TicketRepository
	CategoryRepository
	RequestRepository
}

// NewRepository объединяет хранилища заявок, обращений и категорий.
// При nil pools.Read использует pools.Write для чтения; заявки и обращения разделяют одно хранилище.
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
		RequestRepository:  ticketRepo,
	}
}
