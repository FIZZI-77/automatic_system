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

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func normalizeString(s string) string {
	return strings.TrimSpace(s)
}

func isEmailValid(email string) bool {
	if email == "" {
		return false
	}

	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	// ParseAddress допускает display name, а нам нужен именно голый email.
	return addr.Address == email
}

func isIPValid(ip string) bool {
	return net.ParseIP(ip) != nil
}

func validatePassword(password string) error {
	if strings.TrimSpace(password) == "" {
		return ErrPasswordRequired
	}
	if utf8.RuneCountInString(password) < minPasswordLength {
		return ErrPasswordTooShort
	}
	return nil
}

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

func (in *LogoutInput) Validate() error {
	if in.UserID == uuid.Nil {
		return ErrUserIDRequired
	}
	if in.SessionID == uuid.Nil {
		return ErrSessionIDRequired
	}
	return nil
}

func (in *LogoutAllInput) Validate() error {
	if in.UserID == uuid.Nil {
		return ErrUserIDRequired
	}
	return nil
}

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

func (in *VerifyEmailInput) Validate() error {
	in.Token = normalizeString(in.Token)
	if in.Token == "" {
		return ErrTokenRequired
	}
	return nil
}

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
