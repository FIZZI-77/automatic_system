package models

import (
	"errors"
	"github.com/google/uuid"
	"net"
	"net/mail"
	"strings"
	"unicode/utf8"
)

var (
	ErrEmailRequired        = errors.New("email is required")
	ErrEmailInvalid         = errors.New("email is invalid")
	ErrPasswordRequired     = errors.New("password is required")
	ErrPasswordTooShort     = errors.New("password must be at least 8 characters long")
	ErrUsernameRequired     = errors.New("username is required")
	ErrUsernameTooShort     = errors.New("username must be at least 3 characters long")
	ErrUsernameTooLong      = errors.New("username must be at most 100 characters long")
	ErrClientIDRequired     = errors.New("client_id is required")
	ErrIPRequired           = errors.New("ip is required")
	ErrIPInvalid            = errors.New("ip is invalid")
	ErrUserAgentRequired    = errors.New("user_agent is required")
	ErrRefreshTokenRequired = errors.New("refresh_token is required")
	ErrUserIDRequired       = errors.New("user_id is required")
	ErrSessionIDRequired    = errors.New("session_id is required")
	ErrOldPasswordRequired  = errors.New("old_password is required")
	ErrNewPasswordRequired  = errors.New("new_password is required")
	ErrNewPasswordSameAsOld = errors.New("new_password must be different from old_password")
	ErrTokenRequired        = errors.New("token is required")
)

const (
	minPasswordLength = 8
	minUsernameLength = 3
	maxUsernameLength = 100
)

// normalizeEmail удаляет пробелы по краям адреса и приводит его к нижнему регистру.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// normalizeString возвращает строку без окружающих пробельных символов.
func normalizeString(s string) string {
	return strings.TrimSpace(s)
}

// isEmailValid принимает только адрес без отображаемого имени и дополнительных частей.
// Сравнивает результат mail.ParseAddress с исходной строкой; пустой адрес отклоняет.
func isEmailValid(email string) bool {

	if email == "" {
		return false
	}

	addr, err := mail.ParseAddress(email)

	if err != nil {
		return false
	}

	return addr.Address == email
}

// isIPValid проверяет строковое представление адреса IPv4 или IPv6 через net.ParseIP.
func isIPValid(ip string) bool {
	return net.ParseIP(ip) != nil
}

// validatePassword требует непустой пароль длиной не менее восьми Unicode-символов.
// Возвращает ErrPasswordRequired или ErrPasswordTooShort; пароль не изменяет.
func validatePassword(password string) error {

	if strings.TrimSpace(password) == "" {
		return ErrPasswordRequired
	}

	if utf8.RuneCountInString(password) < minPasswordLength {
		return ErrPasswordTooShort
	}

	return nil
}

// validateUsername проверяет длину имени после удаления окружающих пробелов: 3–100
// Unicode-символов. Исходную строку не изменяет и возвращает соответствующую ошибку имени.
func validateUsername(username string) error {
	username = strings.TrimSpace(username)

	if username == "" {
		return ErrUsernameRequired
	}

	length := utf8.RuneCountInString(username)

	if length < minUsernameLength {
		return ErrUsernameTooShort
	}

	if length > maxUsernameLength {
		return ErrUsernameTooLong
	}

	return nil
}

// Validate нормализует Email и Username, затем проверяет адрес, имя и пароль регистрации.
// Изменяет поля in и возвращает первую ошибку проверки.
func (in *RegisterInput) Validate() error {
	in.Email = normalizeEmail(in.Email)
	in.Username = normalizeString(in.Username)

	if in.Email == "" {
		return ErrEmailRequired
	}

	if !isEmailValid(in.Email) {
		return ErrEmailInvalid
	}

	if err := validateUsername(in.Username); err != nil {
		return err
	}

	if err := validatePassword(in.Password); err != nil {
		return err
	}

	return nil
}

// Validate нормализует Email, ClientID, IP и UserAgent и проверяет обязательные данные входа.
// Проверяет формат адреса почты и IP; совпадение пароля с учётной записью здесь не проверяет.
func (in *LoginInput) Validate() error {
	in.Email = normalizeEmail(in.Email)
	in.ClientID = normalizeString(in.ClientID)
	in.IP = normalizeString(in.IP)
	in.UserAgent = normalizeString(in.UserAgent)

	if in.Email == "" {
		return ErrEmailRequired
	}

	if !isEmailValid(in.Email) {
		return ErrEmailInvalid
	}

	if strings.TrimSpace(in.Password) == "" {
		return ErrPasswordRequired
	}

	if in.ClientID == "" {
		return ErrClientIDRequired
	}

	if in.IP == "" {
		return ErrIPRequired
	}

	if !isIPValid(in.IP) {
		return ErrIPInvalid
	}

	if in.UserAgent == "" {
		return ErrUserAgentRequired
	}

	return nil
}

// Validate удаляет пробелы в данных обновления токенов и проверяет наличие токена,
// клиента, IP и UserAgent. Формат IP проверяет, подлинность токена — нет.
func (in *RefreshInput) Validate() error {
	in.RefreshToken = normalizeString(in.RefreshToken)
	in.ClientID = normalizeString(in.ClientID)
	in.IP = normalizeString(in.IP)
	in.UserAgent = normalizeString(in.UserAgent)

	if in.RefreshToken == "" {
		return ErrRefreshTokenRequired
	}

	if in.ClientID == "" {
		return ErrClientIDRequired
	}

	if in.IP == "" {
		return ErrIPRequired
	}

	if !isIPValid(in.IP) {
		return ErrIPInvalid
	}

	if in.UserAgent == "" {
		return ErrUserAgentRequired
	}

	return nil
}

// Validate требует ненулевые идентификаторы пользователя и закрываемой сессии.
func (in *LogoutInput) Validate() error {

	if in.UserID == uuid.Nil {
		return ErrUserIDRequired
	}

	if in.SessionID == uuid.Nil {
		return ErrSessionIDRequired
	}

	return nil
}

// Validate требует ненулевой идентификатор пользователя для закрытия всех сессий.
func (in *LogoutAllInput) Validate() error {

	if in.UserID == uuid.Nil {
		return ErrUserIDRequired
	}

	return nil
}

// Validate проверяет пользователя, сессию и непустые старый и новый пароли.
// Новый пароль должен содержать не менее восьми Unicode-символов и отличаться от старого.
func (in *ChangePasswordInput) Validate() error {

	if in.UserID == uuid.Nil {
		return ErrUserIDRequired
	}

	if in.SessionID == uuid.Nil {
		return ErrSessionIDRequired
	}

	if strings.TrimSpace(in.OldPassword) == "" {
		return ErrOldPasswordRequired
	}

	if strings.TrimSpace(in.NewPassword) == "" {
		return ErrNewPasswordRequired
	}

	if utf8.RuneCountInString(in.NewPassword) < minPasswordLength {
		return ErrPasswordTooShort
	}

	if in.OldPassword == in.NewPassword {
		return ErrNewPasswordSameAsOld
	}

	return nil
}

// Validate требует идентификатор пользователя и нормализует необязательный Email.
// Если адрес задан, проверяет его формат; пустой адрес допускает.
func (in *SendVerificationEmailInput) Validate() error {

	if in.UserID == uuid.Nil {
		return ErrUserIDRequired
	}

	in.Email = normalizeEmail(in.Email)

	if in.Email != "" && !isEmailValid(in.Email) {
		return ErrEmailInvalid
	}

	return nil
}

// Validate удаляет окружающие пробелы в Token и требует непустое значение.
// Существование, срок и одноразовость токена проверяются при подтверждении почты.
func (in *VerifyEmailInput) Validate() error {
	in.Token = normalizeString(in.Token)

	if in.Token == "" {
		return ErrTokenRequired
	}

	return nil
}

// Validate приводит Email к нижнему регистру без окружающих пробелов и проверяет его формат.
func (in *RequestPasswordResetInput) Validate() error {
	in.Email = normalizeEmail(in.Email)

	if in.Email == "" {
		return ErrEmailRequired
	}

	if !isEmailValid(in.Email) {
		return ErrEmailInvalid
	}

	return nil
}

// Validate нормализует токен сброса и проверяет его наличие и новый пароль.
// Пароль должен быть непустым и содержать не менее восьми Unicode-символов.
func (in *ResetPasswordInput) Validate() error {
	in.Token = normalizeString(in.Token)

	if in.Token == "" {
		return ErrTokenRequired
	}

	if strings.TrimSpace(in.NewPassword) == "" {
		return ErrNewPasswordRequired
	}

	if utf8.RuneCountInString(in.NewPassword) < minPasswordLength {
		return ErrPasswordTooShort
	}

	return nil
}
