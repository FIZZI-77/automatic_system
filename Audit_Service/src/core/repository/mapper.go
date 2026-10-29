package repository

import (
	"audit/models"
	"encoding/json"
	"github.com/google/uuid"
	"strings"
)

type row interface {
	// Scan переносит значения строки в переданные указатели и возвращает ошибку преобразования или чтения.
	Scan(...any) error
}

// scanEntry читает поля записи аудита и декодирует JSON в Data.
// Ошибки Scan, включая отсутствие строки, и декодирования возвращает без замены.
func scanEntry(r row) (*models.Entry, error) {
	entry := new(models.Entry)
	var data []byte

	if err := r.Scan(&entry.ID, &entry.EventID, &entry.Topic, &entry.Action, &entry.ActorID, &entry.EntityType, &entry.EntityID, &entry.RequestID, &entry.TraceID, &data, &entry.OccurredAt, &entry.RecordedAt); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, &entry.Data); err != nil {
		return nil, err
	}

	return entry, nil
}

// scanEntryWithTotal читает запись аудита и записывает оконный счётчик в total,
// затем декодирует Data. total должен быть ненулевым указателем.
func scanEntryWithTotal(r row, total *int64) (*models.Entry, error) {
	entry := new(models.Entry)
	var data []byte

	if err := r.Scan(&entry.ID, &entry.EventID, &entry.Topic, &entry.Action, &entry.ActorID, &entry.EntityType, &entry.EntityID, &entry.RequestID, &entry.TraceID, &data, &entry.OccurredAt, &entry.RecordedAt, total); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, &entry.Data); err != nil {
		return nil, err
	}

	return entry, nil
}

// eventEntity извлекает тип и ID сущности из полей payload в порядке приоритета.
// При отсутствии типа использует первый сегмент event.Type без конечной s;
// пустые значения возвращает как nil.
func eventEntity(event models.Event) (*string, *string) {
	kind := strings.TrimSpace(stringValue(event.Payload, "entity_type", "aggregate_type", "resource_type"))

	if kind == "" {
		kind = strings.TrimSuffix(strings.Split(event.Type, ".")[0], "s")
	}

	id := stringValue(event.Payload, "entity_id", "aggregate_id", "ticket_id", "department_id", "brigade_id", "profile_id", "user_id", "id")
	return pointer(kind), pointer(id)
}

// uuidValue разбирает первое непустое строковое значение среди keys как UUID.
// Отсутствие значения или неверный UUID возвращает как nil.
func uuidValue(data map[string]any, keys ...string) *uuid.UUID {
	id, err := uuid.Parse(stringValue(data, keys...))

	if err != nil {
		return nil
	}

	return &id
}

// metadataValue возвращает первое непустое значение среди keys из headers, обрезая
// пробелы; затем ищет в data. Если значений нет, возвращает nil.
func metadataValue(headers map[string]string, data map[string]any, keys ...string) *string {
	for _, key := range keys {

		if value := strings.TrimSpace(headers[key]); value != "" {
			return &value
		}

	}
	return pointer(stringValue(data, keys...))
}

// stringValue возвращает первое непустое строковое поле в порядке keys.
// Проверяет непустоту без крайних пробелов, но возвращает исходную строку.
func stringValue(data map[string]any, keys ...string) string {
	for _, key := range keys {

		if value, ok := data[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}

	}
	return ""
}

// pointer возвращает указатель на исходную строку либо nil, если она состоит из пробелов или пуста.
func pointer(value string) *string {

	if strings.TrimSpace(value) == "" {
		return nil
	}

	return &value
}
