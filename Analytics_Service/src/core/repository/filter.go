package repository

import (
	"analytics/models"
	"encoding/json"
	"strconv"
	"strings"
)

// buildFilter строит SQL-условия периода и всех заданных измерений с параметрами ?.
// column задаётся внутренним кодом; приоритет, режим назначения и код сбоя приводит к верхнему регистру.
func buildFilter(f models.Filter, column string) (string, []any) {
	parts := []string{"1=1"}
	args := []any{}

	if f.From != nil {
		parts = append(parts, column+">=?")
		args = append(args, *f.From)
	}

	if f.To != nil {
		parts = append(parts, column+"<=?")
		args = append(args, *f.To)
	}

	if f.DepartmentID != nil {
		parts = append(parts, "department_id=?")
		args = append(args, *f.DepartmentID)
	}

	if f.CategoryID != nil {
		parts = append(parts, "category_id=?")
		args = append(args, *f.CategoryID)
	}

	if f.Priority != nil {
		parts = append(parts, "priority=?")
		args = append(args, strings.ToUpper(*f.Priority))
	}

	if f.BrigadeID != nil {
		parts = append(parts, "brigade_id=?")
		args = append(args, *f.BrigadeID)
	}

	if f.AssignmentMode != nil {
		parts = append(parts, "assignment_mode=?")
		args = append(args, strings.ToUpper(*f.AssignmentMode))
	}

	if f.FailureCode != nil {
		parts = append(parts, "failure_code=?")
		args = append(args, strings.ToUpper(*f.FailureCode))
	}

	if f.Success != nil {
		parts = append(parts, "success=?")
		args = append(args, *f.Success)
	}

	return strings.Join(parts, " AND "), args
}

// buildTimeFilter строит включительные ограничения From и To для внутреннего SQL-столбца column.
// Возвращает условие без WHERE и параметры в порядке подстановки.
func buildTimeFilter(filter models.Filter, column string) (string, []any) {
	parts := []string{"1=1"}
	args := make([]any, 0, 2)

	if filter.From != nil {
		parts = append(parts, column+">=?")
		args = append(args, *filter.From)
	}

	if filter.To != nil {
		parts = append(parts, column+"<=?")
		args = append(args, *filter.To)
	}

	return strings.Join(parts, " AND "), args
}

// buildAssignmentDimensions строит условия ведомства, категории, приоритета,
// бригады и режима назначения без периода. Приоритет и режим приводит к верхнему регистру.
func buildAssignmentDimensions(filter models.Filter) (string, []any) {
	parts := []string{"1=1"}
	args := make([]any, 0, 5)
	appendStringFilter := func(value *string, expression string, normalize bool) {

		if value == nil {
			return
		}

		parts = append(parts, expression+"=?")
		argument := *value

		if normalize {
			argument = strings.ToUpper(argument)
		}

		args = append(args, argument)
	}
	appendStringFilter(filter.DepartmentID, "department_id", false)
	appendStringFilter(filter.CategoryID, "category_id", false)
	appendStringFilter(filter.Priority, "priority", true)
	appendStringFilter(filter.BrigadeID, "brigade_id", false)
	appendStringFilter(filter.AssignmentMode, "assignment_mode", true)
	return strings.Join(parts, " AND "), args
}

// buildRoutingDimensions строит условия измерений маршрутизации, включая код сбоя
// и успешность, без временного интервала. Возвращает SQL и параметры ?.
func buildRoutingDimensions(filter models.Filter) (string, []any) {
	parts := []string{"1=1"}
	args := make([]any, 0, 7)
	appendStringFilter := func(value *string, expression string, normalize bool) {

		if value == nil {
			return
		}

		parts = append(parts, expression+"=?")
		argument := *value

		if normalize {
			argument = strings.ToUpper(argument)
		}

		args = append(args, argument)
	}
	appendStringFilter(filter.DepartmentID, "department_id", false)
	appendStringFilter(filter.CategoryID, "category_id", false)
	appendStringFilter(filter.Priority, "priority", true)
	appendStringFilter(filter.BrigadeID, "brigade_id", false)
	appendStringFilter(filter.AssignmentMode, "assignment_mode", true)
	appendStringFilter(filter.FailureCode, "failure_code", true)

	if filter.Success != nil {
		parts = append(parts, "success=?")
		args = append(args, *filter.Success)
	}

	return strings.Join(parts, " AND "), args
}

// buildDispatchFailureDimensions дополняет измерения назначения фильтром кода сбоя
// в верхнем регистре; временной интервал не добавляет.
func buildDispatchFailureDimensions(filter models.Filter) (string, []any) {
	where, args := buildAssignmentDimensions(filter)

	if filter.FailureCode != nil {
		where += " AND failure_code=?"
		args = append(args, strings.ToUpper(*filter.FailureCode))
	}

	return where, args
}

// stringValue возвращает первое непустое строковое значение по keys, рекурсивно
// ища нормализованные имена в картах. Пробелы в найденном значении сохраняет.
func stringValue(data map[string]any, keys ...string) string {
	for _, key := range keys {

		if value, ok := findValue(data, key); ok {
			value, ok := value.(string)

			if !ok || value == "" {
				continue
			}

			return value
		}

	}
	return ""
}

// numberValue рекурсивно ищет поле и преобразует поддерживаемое число,
// json.Number или числовую строку в float64. Отсутствие или ошибка разбора даёт nil.
func numberValue(data map[string]any, key string) *float64 {
	value, ok := findValue(data, key)

	if !ok {
		return nil
	}

	switch value := value.(type) {
	case float64:
		return &value
	case float32:
		converted := float64(value)
		return &converted
	case int:
		converted := float64(value)
		return &converted
	case int64:
		converted := float64(value)
		return &converted
	case json.Number:
		converted, err := value.Float64()

		if err == nil {
			return &converted
		}

	case string:
		converted, err := strconv.ParseFloat(strings.TrimSpace(value), 64)

		if err == nil {
			return &converted
		}

	}
	return nil
}

// numberPathValue извлекает число по точному пути вложенных map[string]any,
// нормализуя имена ключей. Пустой путь, отсутствие или неподходящее значение дают nil.
func numberPathValue(data map[string]any, path ...string) *float64 {

	if len(path) == 0 {
		return nil
	}

	current := data
	for _, key := range path[:len(path)-1] {
		value, ok := directValue(current, key)

		if !ok {
			return nil
		}

		nested, ok := value.(map[string]any)

		if !ok {
			return nil
		}

		current = nested
	}
	value, ok := directValue(current, path[len(path)-1])

	if !ok {
		return nil
	}

	return numericValue(value)
}

// directValue ищет нормализованное имя только на текущем уровне карты.
// При нескольких совпадениях выбор зависит от порядка обхода map.
func directValue(data map[string]any, key string) (any, bool) {
	wanted := normalizeKey(key)
	for candidate, value := range data {

		if normalizeKey(candidate) == wanted {
			return value, true
		}

	}
	return nil, false
}

// numericValue преобразует значение в float64 по правилам numberValue либо возвращает nil.
func numericValue(value any) *float64 {
	return numberValue(map[string]any{"value": value}, "value")
}

// uint64Value извлекает число через float64 и преобразует в uint64 с усечением дроби.
// Отсутствующее или отрицательное значение даёт nil; верхнюю границу не проверяет.
func uint64Value(data map[string]any, key string) *uint64 {
	value := numberValue(data, key)

	if value == nil || *value < 0 {
		return nil
	}

	converted := uint64(*value)
	return &converted
}

// boolValue возвращает первое найденное логическое значение по keys с рекурсивным
// поиском в картах. Строки и числа в bool не преобразует; отсутствие даёт nil.
func boolValue(data map[string]any, keys ...string) *bool {
	for _, key := range keys {
		value, ok := findValue(data, key)

		if !ok {
			continue
		}

		converted, ok := value.(bool)

		if ok {
			return &converted
		}

	}
	return nil
}

// findValue ищет нормализованное имя сначала в текущей карте, затем рекурсивно
// во вложенных map[string]any. Массивы не обходит; порядок выбора между вложенными картами не задан.
func findValue(data map[string]any, key string) (any, bool) {
	wanted := normalizeKey(key)
	for candidate, value := range data {

		if normalizeKey(candidate) == wanted {
			return value, true
		}

	}
	for _, value := range data {
		nested, ok := value.(map[string]any)

		if !ok {
			continue
		}

		if found, ok := findValue(nested, key); ok {
			return found, true
		}

	}
	return nil, false
}

// normalizeKey приводит имя к нижнему регистру и удаляет подчёркивания, дефисы и пробелы.
func normalizeKey(value string) string {
	var builder strings.Builder
	for _, character := range strings.ToLower(value) {

		if character == '_' || character == '-' || character == ' ' {
			continue
		}

		builder.WriteRune(character)
	}
	return builder.String()
}
