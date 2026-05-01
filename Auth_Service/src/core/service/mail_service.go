package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"mime"
	"net"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

type SMTPMailConfig struct {
	Host               string
	Port               int
	Username           string
	Password           string
	FromEmail          string
	FromName           string
	FrontendBaseURL    string
	UseTLS             bool
	UseStartTLS        bool
	InsecureSkipVerify bool
	Timeout            time.Duration
}

type SMTPMailService struct {
	cfg    SMTPMailConfig
	logger *zap.Logger
}

func NewSMTPMailService(cfg SMTPMailConfig, logger *zap.Logger) (*SMTPMailService, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("mail_service: host is empty")
	}
	if cfg.Port <= 0 {
		return nil, fmt.Errorf("mail_service: invalid port")
	}
	if cfg.FromEmail == "" {
		return nil, fmt.Errorf("mail_service: from email is empty")
	}
	if cfg.FrontendBaseURL == "" {
		return nil, fmt.Errorf("mail_service: frontend base url is empty")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	return &SMTPMailService{cfg: cfg, logger: logger}, nil
}

func (s *SMTPMailService) SendVerificationEmail(ctx context.Context, toEmail string, token string) error {

	s.logger.Info("send verification email")

	verifyURL, err := s.buildURL("/verify-email", map[string]string{
		"token": token,
	})
	if err != nil {
		s.logger.Error("build verification email url", zap.Error(err))
		return fmt.Errorf("mail_service: SendVerificationEmail(): build url: %w", err)
	}

	subject := "Подтверждение электронной почты"

	textBody := fmt.Sprintf(
		"Подтверди свою электронную почту, перейдя по ссылке:\n\n%s\n\nЕсли ты не запрашивал это письмо, просто проигнорируй его.",
		verifyURL,
	)

	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Подтверждение почты</title>
</head>
<body>
  <p>Подтверди свою электронную почту, нажав на кнопку ниже.</p>
  <p><a href="%s" target="_blank" rel="noopener noreferrer">Подтвердить почту</a></p>
  <p>Если кнопка не работает, открой ссылку вручную:</p>
  <p>%s</p>
  <p>Если ты не запрашивал это письмо, просто проигнорируй его.</p>
</body>
</html>`, verifyURL, verifyURL)

	s.logger.Info("send verification email successfully")

	return s.send(ctx, []string{toEmail}, subject, textBody, htmlBody)
}

func (s *SMTPMailService) SendPasswordResetEmail(ctx context.Context, toEmail string, token string) error {

	s.logger.Info("send password reset email")

	resetURL, err := s.buildURL("/reset-password", map[string]string{
		"token": token,
	})
	if err != nil {
		s.logger.Error("build reset password email url", zap.Error(err))
		return fmt.Errorf("mail_service: SendPasswordResetEmail(): build url: %w", err)
	}

	subject := "Сброс пароля"

	textBody := fmt.Sprintf(
		"Чтобы сбросить пароль, перейди по ссылке:\n\n%s\n\nЕсли ты не запрашивал сброс пароля, просто проигнорируй это письмо.",
		resetURL,
	)

	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Сброс пароля</title>
</head>
<body>
  <p>Чтобы сбросить пароль, нажми на кнопку ниже.</p>
  <p><a href="%s" target="_blank" rel="noopener noreferrer">Сбросить пароль</a></p>
  <p>Если кнопка не работает, открой ссылку вручную:</p>
  <p>%s</p>
  <p>Если ты не запрашивал сброс пароля, просто проигнорируй это письмо.</p>
</body>
</html>`, resetURL, resetURL)

	s.logger.Info("send password reset email successfully")

	return s.send(ctx, []string{toEmail}, subject, textBody, htmlBody)
}

func (s *SMTPMailService) buildURL(path string, params map[string]string) (string, error) {

	s.logger.Info("build url", zap.String("path", path))

	base, err := url.Parse(strings.TrimRight(s.cfg.FrontendBaseURL, "/"))
	if err != nil {
		s.logger.Error("build url", zap.Error(err))
		return "", fmt.Errorf("invalid frontend base url: %w", err)
	}

	base.Path = strings.TrimRight(base.Path, "/") + path

	q := base.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	base.RawQuery = q.Encode()

	s.logger.Info("build url successfully", zap.String("base", base.String()))

	return base.String(), nil
}

func (s *SMTPMailService) send(
	ctx context.Context,
	to []string,
	subject string,
	textBody string,
	htmlBody string,
) error {
	s.logger.Info("send email")

	msg, err := s.buildMessage(to, subject, textBody, htmlBody)
	if err != nil {
		return fmt.Errorf("mail_service: send(): build message: %w", err)
	}

	if err := s.sendSMTP(ctx, to, msg); err != nil {
		return fmt.Errorf("mail_service: send(): smtp send failed: %w", err)
	}

	s.logger.Info("send email successfully")

	return nil
}

func (s *SMTPMailService) buildMessage(
	to []string,
	subject string,
	textBody string,
	htmlBody string,
) ([]byte, error) {

	boundary := fmt.Sprintf("mixed_%d", time.Now().UnixNano())

	fromHeader := s.cfg.FromEmail
	if s.cfg.FromName != "" {
		fromHeader = fmt.Sprintf("%s <%s>", mime.QEncoding.Encode("UTF-8", s.cfg.FromName), s.cfg.FromEmail)
	}

	subjectHeader := mime.QEncoding.Encode("UTF-8", subject)

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("From: %s\r\n", fromHeader))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(to, ", ")))
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", subjectHeader))
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=%q\r\n", boundary))
	sb.WriteString("\r\n")

	sb.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(textBody)
	sb.WriteString("\r\n")

	sb.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	sb.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	sb.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(htmlBody)
	sb.WriteString("\r\n")

	sb.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	return []byte(sb.String()), nil
}

func (s *SMTPMailService) sendSMTP(ctx context.Context, to []string, msg []byte) error {

	s.logger.Info(" sendSMTP")

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	dialer := &net.Dialer{
		Timeout: s.cfg.Timeout,
	}

	var conn net.Conn
	var err error

	if s.cfg.UseTLS {
		tlsConfig := &tls.Config{
			ServerName:         s.cfg.Host,
			InsecureSkipVerify: s.cfg.InsecureSkipVerify,
		}

		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			s.logger.Warn("smtp send failed", zap.Error(err))
			return fmt.Errorf("tls dial: %w", err)
		}
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			s.logger.Warn("smtp send failed", zap.Error(err))
			return fmt.Errorf("dial: %w", err)
		}
	}

	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		s.logger.Warn("smtp send failed", zap.Error(err))
		return fmt.Errorf("new smtp client: %w", err)
	}
	defer func() {
		_ = client.Close()
	}()

	if !s.cfg.UseTLS && s.cfg.UseStartTLS {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			s.logger.Warn("smtp send failed: no STARTTLS")
			return errors.New("smtp server does not support STARTTLS")
		}

		tlsConfig := &tls.Config{
			ServerName:         s.cfg.Host,
			InsecureSkipVerify: s.cfg.InsecureSkipVerify,
		}

		if err = client.StartTLS(tlsConfig); err != nil {
			s.logger.Warn("smtp send failed", zap.Error(err))
			return fmt.Errorf("starttls: %w", err)
		}
	}

	if s.cfg.Username != "" {
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if err = client.Auth(auth); err != nil {
			s.logger.Warn("smtp send failed", zap.Error(err))
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err = client.Mail(s.cfg.FromEmail); err != nil {
		s.logger.Warn("smtp send failed", zap.Error(err))
		return fmt.Errorf("smtp mail from: %w", err)
	}

	for _, recipient := range to {
		if err = client.Rcpt(recipient); err != nil {
			s.logger.Warn("smtp send failed", zap.Error(err))
			return fmt.Errorf("smtp rcpt to %s: %w", recipient, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		s.logger.Warn("smtp send failed", zap.Error(err))
		return fmt.Errorf("smtp data: %w", err)
	}

	if _, err = w.Write(msg); err != nil {
		_ = w.Close()
		s.logger.Warn("smtp send failed", zap.Error(err))
		return fmt.Errorf("smtp write message: %w", err)
	}

	if err = w.Close(); err != nil {
		s.logger.Warn("smtp send failed", zap.Error(err))
		return fmt.Errorf("smtp close writer: %w", err)
	}

	if err = client.Quit(); err != nil {
		s.logger.Warn("smtp send failed", zap.Error(err))
		return fmt.Errorf("smtp quit: %w", err)
	}

	return nil
}
