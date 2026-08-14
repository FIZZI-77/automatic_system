package repository

import (
	"analytics/models"
	"strings"
)

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
	return strings.Join(parts, " AND "), args
}
func stringValue(data map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := data[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}
func numberValue(data map[string]any, key string) *float64 {
	if value, ok := data[key].(float64); ok {
		return &value
	}
	return nil
}
