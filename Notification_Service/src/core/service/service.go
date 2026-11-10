package service

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"notification/models"
	"notification/src/core/repository"
	"strings"
)

var ErrNotFound = errors.New("not found")

type Publisher interface {
	// Publish передаёт уведомление в канал оперативной доставки пользователю.
	Publish(context.Context, *models.Notification) error
}
type Service struct {
	repo *repository.Repository
	live Publisher
}

// New создаёт сервис уведомлений; nil p отключает публикацию в оперативный канал.
func New(r *repository.Repository, p Publisher) *Service { return &Service{repo: r, live: p} }

// Consume обрабатывает пользовательские события заявок: определяет получателей,
// сохраняет уведомления и задания доставки, затем публикует новые IN_APP-уведомления.
// Остальные события пропускает; ошибки оперативной публикации игнорирует.
func (s *Service) Consume(c context.Context, e models.Event) error {

	if !isUserFacingEvent(e.Type) {
		return nil
	}

	users, err := s.repo.ResolveRecipients(c, e)

	if err != nil {
		return err
	}

	items, err := s.repo.Dispatch(c, e, users)

	if err != nil {
		return err
	}

	for _, v := range items {

		if s.live != nil {
			_ = s.live.Publish(c, v)
		}

	}
	return nil
}

// isUserFacingEvent проверяет, относится ли тип к уведомлениям о создании,
// назначении, статусе, завершении, отмене заявки или результате итогового отчёта.
// Крайние пробелы и регистр не учитываются.
func isUserFacingEvent(eventType string) bool {
	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "ticket.created",
		"ticket.assigned",
		"ticket.status_changed",
		"ticket.completed",
		"ticket.canceled",
		"ticket.completion_report.generated.v1",
		"ticket.completion_report.failed.v1":
		return true
	default:
		return false
	}
}

// List возвращает страницу уведомлений пользователя, общее и непрочитанное число
// в отфильтрованном наборе. x=true оставляет только непрочитанные; пустая страница даёт нулевые счётчики.
func (s *Service) List(c context.Context, u uuid.UUID, x *bool, l, o int32) ([]*models.Notification, int64, int64, error) {
	return s.repo.List(c, u, x, l, o)
}

// MarkRead отмечает уведомление пользователя прочитанным, сохраняя время первого
// прочтения. Отсутствие уведомления у пользователя возвращает как ErrNotFound.
func (s *Service) MarkRead(c context.Context, u, id uuid.UUID) (*models.Notification, error) {
	v, e := s.repo.MarkRead(c, u, id)
	return v, mapErr(e)
}

// MarkAllRead отмечает все непрочитанные уведомления пользователя и возвращает число изменений.
func (s *Service) MarkAllRead(c context.Context, u uuid.UUID) (int64, error) {
	return s.repo.MarkAllRead(c, u)
}

// GetPreferences возвращает настройки пользователя, создавая значения по умолчанию при отсутствии.
func (s *Service) GetPreferences(c context.Context, u uuid.UUID) (*models.Preferences, error) {
	return s.repo.GetPreferences(c, u)
}

// SavePreferences создаёт или заменяет настройки каналов и контактов пользователя,
// записывая актуальное время обновления в v.
func (s *Service) SavePreferences(c context.Context, v *models.Preferences) (*models.Preferences, error) {
	return s.repo.SavePreferences(c, v)
}

// RegisterDevice нормализует v.Platform и требует непустой токен и платформу android,
// ios или web. Сохраняет устройство по токену, заполняя в v ID, активность и временные метки.
func (s *Service) RegisterDevice(c context.Context, v *models.Device) (*models.Device, error) {
	v.Platform = strings.ToLower(strings.TrimSpace(v.Platform))

	if v.Token == "" || (v.Platform != "android" && v.Platform != "ios" && v.Platform != "web") {
		return nil, errors.New("invalid device")
	}

	return s.repo.RegisterDevice(c, v)
}

// DeleteDevice деактивирует устройство пользователя и возвращает его запись.
// Отсутствующее или чужое устройство даёт ErrNotFound.
func (s *Service) DeleteDevice(c context.Context, u, id uuid.UUID) (*models.Device, error) {
	v, e := s.repo.DeleteDevice(c, u, id)
	return v, mapErr(e)
}

// UpsertTemplate требует непустые тип события, тело и канал, затем создаёт
// или заменяет шаблон. Хранилище заполняет в v ID и временные метки.
func (s *Service) UpsertTemplate(c context.Context, v *models.Template) (*models.Template, error) {

	if v.EventType == "" || v.Body == "" || v.Channel == "" {
		return nil, errors.New("invalid template")
	}

	return s.repo.UpsertTemplate(c, v)
}

// ListTemplates возвращает страницу шаблонов по событию и каналу с общим счётчиком,
// равным нулю на пустой странице.
func (s *Service) ListTemplates(c context.Context, e, ch *string, l, o int32) ([]*models.Template, int64, error) {
	return s.repo.ListTemplates(c, e, ch, l, o)
}

// ListDeliveries возвращает страницу заданий доставки по статусу и каналу с общим
// счётчиком, равным нулю на пустой странице.
func (s *Service) ListDeliveries(c context.Context, st, ch *string, l, o int32) ([]*models.Delivery, int64, error) {
	return s.repo.ListDeliveries(c, st, ch, l, o)
}

// mapErr заменяет pgx.ErrNoRows на ErrNotFound, остальные ошибки и nil сохраняет.
func mapErr(e error) error {

	if errors.Is(e, pgx.ErrNoRows) {
		return ErrNotFound
	}

	return e
}
