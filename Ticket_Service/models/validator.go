package models

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

const (
	DefaultLimit = int32(20)
	MaxLimit     = int32(100)
)

// validateUUID отклоняет нулевой UUID; field используется в сообщении об ошибке.
func validateUUID(value uuid.UUID, field string) error {

	if value == uuid.Nil {
		return fmt.Errorf("%s is required", field)
	}

	return nil
}

// validateOptionalUUID допускает nil, но отклоняет указатель на нулевой UUID.
func validateOptionalUUID(value *uuid.UUID, field string) error {

	if value == nil {
		return nil
	}

	if *value == uuid.Nil {
		return fmt.Errorf("%s must be valid uuid", field)
	}

	return nil
}

// validateText проверяет непустой текст после удаления пробелов по краям.
// maxLen ограничивает длину в байтах; исходное значение не изменяется.
func validateText(value string, field string, maxLen int) error {
	value = strings.TrimSpace(value)

	if value == "" {
		return fmt.Errorf("%s is required", field)
	}

	if len(value) > maxLen {
		return fmt.Errorf("%s must be less than %d characters", field, maxLen)
	}

	return nil
}

// validateOptionalText допускает nil; заданный текст должен быть непустым после TrimSpace
// и занимать не более maxLen байтов. Значение по указателю не изменяет.
func validateOptionalText(value *string, field string, maxLen int) error {

	if value == nil {
		return nil
	}

	trimmed := strings.TrimSpace(*value)

	if trimmed == "" {
		return fmt.Errorf("%s cannot be empty", field)
	}

	if len(trimmed) > maxLen {
		return fmt.Errorf("%s must be less than %d characters", field, maxLen)
	}

	return nil
}

// validateCoordinates проверяет широту в пределах [-90, 90] и долготу [-180, 180].
func validateCoordinates(latitude float64, longitude float64) error {

	if latitude < -90 || latitude > 90 {
		return errors.New("latitude must be between -90 and 90")
	}

	if longitude < -180 || longitude > 180 {
		return errors.New("longitude must be between -180 and 180")
	}

	return nil
}

// normalizeLimitOffset подставляет размер страницы 20 для неположительного limit,
// ограничивает его значением 100 и заменяет отрицательное смещение нулём.
func normalizeLimitOffset(limit int32, offset int32) (int32, int32) {

	if limit <= 0 {
		limit = DefaultLimit
	}

	if limit > MaxLimit {
		limit = MaxLimit
	}

	if offset < 0 {
		offset = 0
	}

	return limit, offset
}

// Validate проверяет обязательные идентификаторы, текст, приоритет, координаты
// и необязательную связь с объектом перед созданием заявки.
func (in *CreateTicketInput) Validate() error {

	if in == nil {
		return errors.New("create ticket input is nil")
	}

	if err := validateUUID(in.DepartmentID, "department_id"); err != nil {
		return err
	}

	if err := validateUUID(in.CategoryID, "category_id"); err != nil {
		return err
	}

	if err := validateUUID(in.UserID, "user_id"); err != nil {
		return err
	}

	if err := validateText(in.Title, "title", 255); err != nil {
		return err
	}

	if err := validateText(in.Description, "description", 3000); err != nil {
		return err
	}

	if !in.Priority.IsValid() {
		return errors.New("priority is invalid")
	}

	if err := validateText(in.Address, "address", 500); err != nil {
		return err
	}

	if err := validateCoordinates(in.Latitude, in.Longitude); err != nil {
		return err
	}

	return nil
}

// Validate проверяет параметры обращения и согласованность внешних идентификаторов.
// ExternalSystemID и ExternalID должны быть заданы вместе; nil-вход отклоняется.
func (in *CreateRequestInput) Validate() error {

	if in == nil {
		return errors.New("create request input is nil")
	}

	if err := validateUUID(in.DepartmentID, "department_id"); err != nil {
		return err
	}

	if err := validateUUID(in.CategoryID, "category_id"); err != nil {
		return err
	}

	if err := validateUUID(in.UserID, "user_id"); err != nil {
		return err
	}

	if err := validateText(in.Title, "title", 255); err != nil {
		return err
	}

	if err := validateText(in.Description, "description", 3000); err != nil {
		return err
	}

	if !in.Priority.IsValid() {
		return errors.New("priority is invalid")
	}

	if err := validateText(in.Address, "address", 500); err != nil {
		return err
	}

	if err := validateCoordinates(in.Latitude, in.Longitude); err != nil {
		return err
	}

	if err := validateOptionalUUID(in.AssetID, "asset_id"); err != nil {
		return err
	}

	if err := validateOptionalUUID(in.ExternalSystemID, "external_system_id"); err != nil {
		return err
	}

	if in.ExternalSystemID == nil && in.ExternalID != nil {
		return errors.New("external_system_id is required with external_id")
	}

	if in.ExternalSystemID != nil {

		if err := validateOptionalText(in.ExternalID, "external_id", 255); err != nil {
			return err
		}

		if in.ExternalID == nil {
			return errors.New("external_id is required with external_system_id")
		}

	}

	return nil
}

// Validate требует идентификаторы инцидента, обращения, исполнителя и причину до 1000 байтов.
// Отклоняет присоединение обращения к самому себе.
func (in *AttachRequestInput) Validate() error {

	if in == nil {
		return errors.New("attach request input is nil")
	}

	if err := validateUUID(in.IncidentID, "incident_id"); err != nil {
		return err
	}

	if err := validateUUID(in.RequestID, "request_id"); err != nil {
		return err
	}

	if err := validateUUID(in.ChangedBy, "changed_by"); err != nil {
		return err
	}

	if err := validateText(in.Reason, "reason", 1000); err != nil {
		return err
	}

	if in.IncidentID == in.RequestID {
		return errors.New("request cannot be attached to itself")
	}

	return nil
}

// Validate требует идентификаторы обращения и исполнителя, а также непустую причину
// отсоединения длиной не более 1000 байтов.
func (in *DetachRequestInput) Validate() error {

	if in == nil {
		return errors.New("detach request input is nil")
	}

	if err := validateUUID(in.RequestID, "request_id"); err != nil {
		return err
	}

	if err := validateUUID(in.ChangedBy, "changed_by"); err != nil {
		return err
	}

	return validateText(in.Reason, "reason", 1000)
}

// Validate проверяет идентификатор инцидента и изменяет Limit и Offset,
// приводя их к допустимым параметрам страницы.
func (in *ListIncidentRequestsInput) Validate() error {

	if in == nil {
		return errors.New("list incident requests input is nil")
	}

	if err := validateUUID(in.IncidentID, "incident_id"); err != nil {
		return err
	}

	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)

	return nil
}

// Validate проверяет имя источника, код ClientID, автора регистрации и необязательный
// департамент. ClientID должен занимать 3–100 байтов и соответствовать isValidCode.
func (in *RegisterIntegrationInput) Validate() error {

	if in == nil {
		return errors.New("register integration input is nil")
	}

	if err := validateText(in.Name, "name", 255); err != nil {
		return err
	}

	if err := validateText(in.ClientID, "client_id", 100); err != nil {
		return err
	}

	if len(strings.TrimSpace(in.ClientID)) < 3 {
		return errors.New("client_id must be at least 3 characters")
	}

	if !isValidCode(in.ClientID) {
		return errors.New("client_id must contain only lowercase letters, digits, underscore or hyphen")
	}

	if err := validateOptionalUUID(in.AllowedDepartmentID, "allowed_department_id"); err != nil {
		return err
	}

	return validateUUID(in.CreatedBy, "created_by")
}

// Validate проверяет непустые ClientID и Secret с ограничениями 100 и 255 байтов.
// Совпадение секрета с сохранённым хешем эта проверка не устанавливает.
func (in *AuthenticateIntegrationInput) Validate() error {

	if in == nil {
		return errors.New("authenticate integration input is nil")
	}

	if err := validateText(in.ClientID, "client_id", 100); err != nil {
		return err
	}

	return validateText(in.Secret, "secret", 255)
}

// Validate проверяет наличие ненулевого идентификатора запрашиваемой заявки.
func (in *GetTicketInput) Validate() error {

	if in == nil {
		return errors.New("get ticket input is nil")
	}

	return validateUUID(in.TicketID, "ticket_id")
}

// Validate проверяет фильтры и порядок дат, затем нормализует сортировку и страницу.
// При отсутствии сортировки устанавливает created_at по убыванию; изменяет in.
func (in *ListTicketsInput) Validate() error {

	if in == nil {
		return errors.New("list tickets input is nil")
	}

	if err := validateOptionalUUID(in.DepartmentID, "department_id"); err != nil {
		return err
	}

	if err := validateOptionalUUID(in.UserID, "user_id"); err != nil {
		return err
	}

	if err := validateOptionalUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}

	if err := validateOptionalUUID(in.CategoryID, "category_id"); err != nil {
		return err
	}

	if in.Status != nil && !in.Status.IsValid() {
		return errors.New("status is invalid")
	}

	if in.Priority != nil && !in.Priority.IsValid() {
		return errors.New("priority is invalid")
	}

	if in.CreatedFrom != nil && in.CreatedTo != nil && in.CreatedFrom.After(*in.CreatedTo) {
		return errors.New("created_from must be before created_to")
	}

	if in.SortBy == "" {
		in.SortBy = TicketSortByCreatedAt
	}

	if !in.SortBy.IsValid() {
		return errors.New("sort_by is invalid")
	}

	if in.SortOrder == "" {
		in.SortOrder = SortOrderDesc
	}

	if !in.SortOrder.IsValid() {
		return errors.New("sort_order is invalid")
	}

	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)

	return nil
}

// Validate проверяет переданные поля изменения и обязательного исполнителя UpdatedBy.
// Координаты допускаются только парой; отсутствующие необязательные поля не проверяются.
func (in *UpdateTicketInput) Validate() error {

	if in == nil {
		return errors.New("update ticket input is nil")
	}

	if err := validateUUID(in.TicketID, "ticket_id"); err != nil {
		return err
	}

	if err := validateOptionalText(in.Title, "title", 255); err != nil {
		return err
	}

	if err := validateOptionalText(in.Description, "description", 3000); err != nil {
		return err
	}

	if err := validateOptionalUUID(in.CategoryID, "category_id"); err != nil {
		return err
	}

	if in.Priority != nil && !in.Priority.IsValid() {
		return errors.New("priority is invalid")
	}

	if err := validateOptionalText(in.Address, "address", 500); err != nil {
		return err
	}

	if (in.Latitude == nil && in.Longitude != nil) || (in.Latitude != nil && in.Longitude == nil) {
		return errors.New("latitude and longitude must be provided together")
	}

	if in.Latitude != nil && in.Longitude != nil {

		if err := validateCoordinates(*in.Latitude, *in.Longitude); err != nil {
			return err
		}

	}

	if in.UpdatedBy == nil {
		return errors.New("updated_by is required")
	}

	if err := validateUUID(*in.UpdatedBy, "updated_by"); err != nil {
		return err
	}

	return nil
}

// Validate проверяет параметры смены состояния, исполнителя и допустимость нового статуса.
// Возможность перехода из текущего состояния проверяется при выполнении операции.
func (in *ChangeTicketStatusInput) Validate() error {

	if in == nil {
		return errors.New("change ticket status input is nil")
	}

	if err := validateUUID(in.TicketID, "ticket_id"); err != nil {
		return err
	}

	if !in.NewStatus.IsValid() {
		return errors.New("new_status is invalid")
	}

	if err := validateUUID(in.ChangedBy, "changed_by"); err != nil {
		return err
	}

	if err := validateOptionalText(in.Comment, "comment", 1000); err != nil {
		return err
	}

	return nil
}

// Validate проверяет идентификаторы заявки, бригады и назначающего исполнителя,
// а также ограничение необязательного комментария.
func (in *AssignBrigadeInput) Validate() error {

	if in == nil {
		return errors.New("assign brigade input is nil")
	}

	if err := validateUUID(in.TicketID, "ticket_id"); err != nil {
		return err
	}

	if err := validateUUID(in.BrigadeID, "brigade_id"); err != nil {
		return err
	}

	if err := validateUUID(in.AssignedBy, "assigned_by"); err != nil {
		return err
	}

	if err := validateOptionalText(in.Comment, "comment", 1000); err != nil {
		return err
	}

	return nil
}

// Validate проверяет идентификаторы заявки и исполнителя и обязательную причину отмены.
func (in *CancelTicketInput) Validate() error {

	if in == nil {
		return errors.New("cancel ticket input is nil")
	}

	if err := validateUUID(in.TicketID, "ticket_id"); err != nil {
		return err
	}

	if err := validateUUID(in.CanceledBy, "canceled_by"); err != nil {
		return err
	}

	if err := validateText(in.Reason, "reason", 1000); err != nil {
		return err
	}

	return nil
}

// Validate проверяет идентификаторы заявки и завершающего исполнителя и комментарий.
// Фактическое состояние заявки и право завершения здесь не проверяются.
func (in *CompleteTicketInput) Validate() error {

	if in == nil {
		return errors.New("complete ticket input is nil")
	}

	if err := validateUUID(in.TicketID, "ticket_id"); err != nil {
		return err
	}

	if err := validateUUID(in.CompletedBy, "completed_by"); err != nil {
		return err
	}

	if err := validateOptionalText(in.Comment, "comment", 1000); err != nil {
		return err
	}

	return nil
}

// Validate проверяет идентификатор заявки и нормализует параметры страницы истории.
func (in *GetTicketStatusHistoryInput) Validate() error {

	if in == nil {
		return errors.New("get ticket status history input is nil")
	}

	if err := validateUUID(in.TicketID, "ticket_id"); err != nil {
		return err
	}

	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)

	return nil
}

// Validate проверяет код, название и необязательное описание новой категории.
func (in *CreateCategoryInput) Validate() error {

	if in == nil {
		return errors.New("create category input is nil")
	}

	if err := validateText(in.Code, "code", 100); err != nil {
		return err
	}

	if !isValidCode(in.Code) {
		return errors.New("code must contain only lowercase letters, digits, underscore or hyphen")
	}

	if err := validateText(in.Name, "name", 255); err != nil {
		return err
	}

	if err := validateOptionalText(in.Description, "description", 1000); err != nil {
		return err
	}

	return nil
}

// Validate проверяет ненулевой идентификатор запрашиваемой категории.
func (in *GetCategoryInput) Validate() error {

	if in == nil {
		return errors.New("get category input is nil")
	}

	return validateUUID(in.CategoryID, "category_id")
}

// Validate нормализует размер страницы и смещение списка категорий, изменяя in.
func (in *ListCategoriesInput) Validate() error {

	if in == nil {
		return errors.New("list categories input is nil")
	}

	in.Limit, in.Offset = normalizeLimitOffset(in.Limit, in.Offset)

	return nil
}

// Validate проверяет идентификатор категории и наличие хотя бы одного изменяемого поля.
// Для заданных названия и описания проверяет текстовые ограничения.
func (in *UpdateCategoryInput) Validate() error {

	if in == nil {
		return errors.New("update category input is nil")
	}

	if err := validateUUID(in.CategoryID, "category_id"); err != nil {
		return err
	}

	if err := validateOptionalText(in.Name, "name", 255); err != nil {
		return err
	}

	if err := validateOptionalText(in.Description, "description", 1000); err != nil {
		return err
	}

	if in.Name == nil && in.Description == nil && in.IsActive == nil {
		return errors.New("at least one field must be provided for update")
	}

	return nil
}

// Validate проверяет ненулевой идентификатор удаляемой категории.
func (in *DeleteCategoryInput) Validate() error {

	if in == nil {
		return errors.New("delete category input is nil")
	}

	return validateUUID(in.CategoryID, "category_id")
}

// isValidCode допускает только строчные латинские буквы, цифры, подчёркивание и дефис.
// Пустую строку не отклоняет; обязательность кода проверяется отдельно.
func isValidCode(code string) bool {
	code = strings.TrimSpace(code)

	if code == "" {
		return false
	}

	for _, r := range code {

		if r >= 'a' && r <= 'z' {
			continue
		}

		if r >= '0' && r <= '9' {
			continue
		}

		if r == '_' || r == '-' {
			continue
		}

		return false
	}

	return true
}
