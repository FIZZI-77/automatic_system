package repository

import "strings"

// sanitize создаёт копию карты, заменяя чувствительные поля на [REDACTED].
// Обрабатывает вложенные map[string]any и такие карты внутри []any;
// остальные значения переносит как есть, исходную карту не изменяет.
func sanitize(values map[string]any) map[string]any {
	result := make(map[string]any, len(values))
	for key, value := range values {

		if sensitive(key) {
			result[key] = "[REDACTED]"
			continue
		}

		switch item := value.(type) {
		case map[string]any:
			result[key] = sanitize(item)
		case []any:
			copy := make([]any, len(item))
			for i, child := range item {

				if nested, ok := child.(map[string]any); ok {
					copy[i] = sanitize(nested)
				} else {
					copy[i] = child
				}

			}
			result[key] = copy
		default:
			result[key] = value
		}
	}
	return result
}

// sensitive сообщает, содержит ли имя поля признак пароля, токена, секрета,
// авторизации или закрытого ключа; регистр не учитывается.
func sensitive(key string) bool {
	key = strings.ToLower(key)
	for _, part := range []string{"password", "secret", "token", "authorization", "private_key", "api_key", "access_key"} {

		if strings.Contains(key, part) {
			return true
		}

	}
	return false
}
