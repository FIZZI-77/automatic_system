package service

import (
	"context"

	"ticket/models"
	"ticket/src/core/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type TicketService interface {
	// CreateTicket создаёт заявку после проверки данных и полномочий исполнителя.
	// Обычный пользователь может создавать заявку только от своего имени.
	// При ключе идемпотентности возвращает сохранённый результат повторного запроса.
	CreateTicket(ctx context.Context, in *models.CreateTicketInput) (*models.CreateTicketResult, error)
	// GetTicket возвращает заявку по идентификатору после проверки права чтения.
	// При недопустимом входе возвращает ErrValidation, при отсутствии доступа — ErrPermissionDenied.
	GetTicket(ctx context.Context, in *models.GetTicketInput) (*models.GetTicketResult, error)
	// ListTickets возвращает страницу заявок и общее количество с учётом роли исполнителя.
	// Изменяет фильтры in: диспетчеру оставляет его департамент, работнику — его бригаду,
	// обычному пользователю — собственные заявки. Администратор сохраняет переданные фильтры.
	ListTickets(ctx context.Context, in *models.ListTicketsInput) (*models.ListTicketsResult, error)
	// UpdateTicket проверяет частичное изменение заявки и передаёт его репозиторию идемпотентно.
	// При ключе идемпотентности повторяет ранее сохранённый результат.
	UpdateTicket(ctx context.Context, in *models.UpdateTicketInput) (*models.UpdateTicketResult, error)

	// ChangeTicketStatus идемпотентно меняет состояние заявки после проверки данных и доступа.
	// Работник своей назначенной бригады может выбрать только IN_PROGRESS; остальные
	// изменения требуют права управления заявкой. Допустимость перехода проверяет репозиторий.
	ChangeTicketStatus(ctx context.Context, in *models.ChangeTicketStatusInput) (*models.ChangeTicketStatusResult, error)
	// AssignBrigade проверяет назначение бригады и право управления заявкой.
	// Выполняет изменение через механизм идемпотентности, возвращая обновлённую заявку.
	AssignBrigade(ctx context.Context, in *models.AssignBrigadeInput) (*models.AssignBrigadeResult, error)
	// CancelTicket отменяет заявку с проверкой входных данных и полномочий исполнителя.
	// Операция выполняется идемпотентно; допустимость отмены проверяет репозиторий.
	CancelTicket(ctx context.Context, in *models.CancelTicketInput) (*models.CancelTicketResult, error)
	// CompleteTicket идемпотентно завершает заявку после проверки данных и полномочий.
	// Разрешает действие управляющему заявкой либо работнику назначенной бригады;
	// переход состояния и ограничения составного инцидента проверяет репозиторий.
	CompleteTicket(ctx context.Context, in *models.CompleteTicketInput) (*models.CompleteTicketResult, error)
	// SubmitTicketFeedback передаёт сохранение оценки заявки репозиторию.
	// Проверки автора, состояния заявки и допустимости оценки выполняются в хранилище.
	SubmitTicketFeedback(ctx context.Context, in *models.SubmitTicketFeedbackInput) (*models.TicketFeedback, error)
	// GetTicketFeedback запрашивает оценку заявки у репозитория вместе с проверками доступа.
	GetTicketFeedback(ctx context.Context, in *models.GetTicketFeedbackInput) (*models.TicketFeedback, error)

	// GetTicketStatusHistory возвращает страницу истории и общее количество переходов заявки.
	// Проверяет входные данные и право чтения заявки перед запросом истории.
	GetTicketStatusHistory(ctx context.Context, in *models.GetTicketStatusHistoryInput) (*models.GetTicketStatusHistoryResult, error)

	// CreateRequest проверяет обращение и передаёт его транзакционное создание репозиторию.
	// Результат содержит обращение, связанный инцидент и признак найденного совпадения.
	CreateRequest(ctx context.Context, in *models.CreateRequestInput) (*models.CreateRequestResult, error)
	// AttachRequest присоединяет обращение к инциденту, в том числе другого департамента.
	// Требует право управления обращением; для одного департамента также проверяет
	// право управления инцидентом. Ошибки проверки данных и доступа возвращает вызывающему.
	AttachRequest(ctx context.Context, in *models.AttachRequestInput) (*models.Ticket, error)
	// DetachRequest отсоединяет обращение от инцидента после проверки входа и права управления.
	// Изменение связи и обязательную причину передаёт репозиторию.
	DetachRequest(ctx context.Context, in *models.DetachRequestInput) (*models.Ticket, error)
	// ListIncidentRequests возвращает страницу частей инцидента и их общее количество.
	// Разрешает доступ при праве управления инцидентом, роли admin или наличии части
	// департамента исполнителя; иначе возвращает ErrPermissionDenied.
	ListIncidentRequests(ctx context.Context, in *models.ListIncidentRequestsInput) ([]*models.Ticket, int64, error)
}

type CategoryService interface {
	// CreateCategory проверяет данные и идемпотентно создаёт категорию.
	// Требует роль admin или dispatcher; иначе возвращает ErrPermissionDenied.
	CreateCategory(ctx context.Context, in *models.CreateCategoryInput) (*models.CreateCategoryResult, error)
	// GetCategory возвращает категорию по идентификатору после проверки входных данных.
	// Отдельного ограничения по роли не вводит; ошибки хранилища возвращает с контекстом операции.
	GetCategory(ctx context.Context, in *models.GetCategoryInput) (*models.GetCategoryResult, error)
	// ListCategories возвращает страницу категорий и общее количество записей.
	// Проверяет и нормализует входные параметры через Validate перед запросом к хранилищу.
	ListCategories(ctx context.Context, in *models.ListCategoriesInput) (*models.ListCategoriesResult, error)
	// UpdateCategory проверяет частичные изменения и идемпотентно обновляет категорию.
	// Требует роль admin или dispatcher; возвращает изменённую запись либо ошибку.
	UpdateCategory(ctx context.Context, in *models.UpdateCategoryInput) (*models.UpdateCategoryResult, error)
	// DeleteCategory идемпотентно удаляет категорию после проверки входа и привилегированной роли.
	// Возвращает удалённую запись; ограничения удаления проверяет репозиторий.
	DeleteCategory(ctx context.Context, in *models.DeleteCategoryInput) (*models.DeleteCategoryResult, error)
}

type ReportService interface {
	// CreateWorkReport проверяет входные данные отчёта и передаёт сохранение репозиторию.
	// Ошибку валидации оборачивает в ErrValidation.
	CreateWorkReport(ctx context.Context, in *models.CreateWorkReportInput) (*models.WorkReport, error)
	// ListWorkReports возвращает отчёты заявки после проверки права чтения её карточки.
	// При отсутствии доступа возвращает ErrPermissionDenied.
	ListWorkReports(ctx context.Context, ticketID, actorID uuid.UUID, brigadeID, departmentID *uuid.UUID, roles []string) ([]*models.WorkReport, error)
}

type Service struct {
	TicketService
	CategoryService
	ReportService
	IntegrationService
}

// NewService создаёт службы заявок, категорий, отчётов и интеграций с общим репозиторием.
// Если logger равен nil, использует журнал без вывода.
func NewService(repo *repository.Repository, logger *zap.Logger) *Service {

	if logger == nil {
		logger = zap.NewNop()
	}

	return &Service{
		TicketService:      NewTicketServiceStruct(repo, logger),
		CategoryService:    NewCategoryServiceStruct(repo, logger),
		ReportService:      NewReportService(repo),
		IntegrationService: NewIntegrationServiceStruct(repo),
	}
}
