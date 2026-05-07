package service

import (
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func validSMTPMailConfig() SMTPMailConfig {
	return SMTPMailConfig{
		Host:            "localhost",
		Port:            1025,
		Username:        "user",
		Password:        "password",
		FromEmail:       "noreply@example.com",
		FromName:        "Auth Service",
		FrontendBaseURL: "https://frontend.example.com",
		UseTLS:          false,
		UseStartTLS:     false,
		Timeout:         5 * time.Second,
	}
}

func TestNewSMTPMailService_Success(t *testing.T) {
	cfg := validSMTPMailConfig()

	svc, err := NewSMTPMailService(cfg, zap.NewNop())

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if svc == nil {
		t.Fatal("expected service, got nil")
	}

	if svc.cfg.Host != cfg.Host {
		t.Fatalf("expected host %s, got %s", cfg.Host, svc.cfg.Host)
	}

	if svc.cfg.Port != cfg.Port {
		t.Fatalf("expected port %d, got %d", cfg.Port, svc.cfg.Port)
	}
}

func TestNewSMTPMailService_DefaultTimeout(t *testing.T) {
	cfg := validSMTPMailConfig()
	cfg.Timeout = 0

	svc, err := NewSMTPMailService(cfg, zap.NewNop())

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if svc.cfg.Timeout != 10*time.Second {
		t.Fatalf("expected default timeout 10s, got %v", svc.cfg.Timeout)
	}
}

func TestNewSMTPMailService_EmptyHost(t *testing.T) {
	cfg := validSMTPMailConfig()
	cfg.Host = ""

	svc, err := NewSMTPMailService(cfg, zap.NewNop())

	if svc != nil {
		t.Fatal("expected nil service")
	}

	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "host is empty") {
		t.Fatalf("expected host error, got %v", err)
	}
}

func TestNewSMTPMailService_InvalidPort(t *testing.T) {
	cfg := validSMTPMailConfig()
	cfg.Port = 0

	svc, err := NewSMTPMailService(cfg, zap.NewNop())

	if svc != nil {
		t.Fatal("expected nil service")
	}

	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("expected invalid port error, got %v", err)
	}
}

func TestNewSMTPMailService_EmptyFromEmail(t *testing.T) {
	cfg := validSMTPMailConfig()
	cfg.FromEmail = ""

	svc, err := NewSMTPMailService(cfg, zap.NewNop())

	if svc != nil {
		t.Fatal("expected nil service")
	}

	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "from email is empty") {
		t.Fatalf("expected from email error, got %v", err)
	}
}

func TestNewSMTPMailService_EmptyFrontendBaseURL(t *testing.T) {
	cfg := validSMTPMailConfig()
	cfg.FrontendBaseURL = ""

	svc, err := NewSMTPMailService(cfg, zap.NewNop())

	if svc != nil {
		t.Fatal("expected nil service")
	}

	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "frontend base url is empty") {
		t.Fatalf("expected frontend base url error, got %v", err)
	}
}

func TestSMTPMailService_buildURL_VerifyEmail(t *testing.T) {
	svc, err := NewSMTPMailService(validSMTPMailConfig(), zap.NewNop())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	got, err := svc.buildURL("/verify-email", map[string]string{
		"token": "abc123",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	expected := "https://frontend.example.com/verify-email?token=abc123"
	if got != expected {
		t.Fatalf("expected url %s, got %s", expected, got)
	}
}

func TestSMTPMailService_buildURL_ResetPassword(t *testing.T) {
	svc, err := NewSMTPMailService(validSMTPMailConfig(), zap.NewNop())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	got, err := svc.buildURL("/reset-password", map[string]string{
		"token": "reset-token",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	expected := "https://frontend.example.com/reset-password?token=reset-token"
	if got != expected {
		t.Fatalf("expected url %s, got %s", expected, got)
	}
}

func TestSMTPMailService_buildURL_TrimsTrailingSlash(t *testing.T) {
	cfg := validSMTPMailConfig()
	cfg.FrontendBaseURL = "https://frontend.example.com/"

	svc, err := NewSMTPMailService(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	got, err := svc.buildURL("/verify-email", map[string]string{
		"token": "abc123",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	expected := "https://frontend.example.com/verify-email?token=abc123"
	if got != expected {
		t.Fatalf("expected url %s, got %s", expected, got)
	}
}

func TestSMTPMailService_buildURL_EncodesToken(t *testing.T) {
	svc, err := NewSMTPMailService(validSMTPMailConfig(), zap.NewNop())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	got, err := svc.buildURL("/verify-email", map[string]string{
		"token": "a b+c/=",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !strings.Contains(got, "token=a+b%2Bc%2F%3D") {
		t.Fatalf("expected encoded token in url, got %s", got)
	}
}

func TestSMTPMailService_buildURL_WithBasePath(t *testing.T) {
	cfg := validSMTPMailConfig()
	cfg.FrontendBaseURL = "https://frontend.example.com/app"

	svc, err := NewSMTPMailService(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	got, err := svc.buildURL("/verify-email", map[string]string{
		"token": "abc123",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	expected := "https://frontend.example.com/app/verify-email?token=abc123"
	if got != expected {
		t.Fatalf("expected url %s, got %s", expected, got)
	}
}

func TestSMTPMailService_buildMessage_Success(t *testing.T) {
	svc, err := NewSMTPMailService(validSMTPMailConfig(), zap.NewNop())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	msg, err := svc.buildMessage(
		[]string{"user@example.com"},
		"Тестовая тема",
		"plain text body",
		"<p>html body</p>",
	)

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	body := string(msg)

	if !strings.Contains(body, "From:") {
		t.Fatal("expected From header")
	}

	if !strings.Contains(body, "To: user@example.com") {
		t.Fatal("expected To header")
	}

	if !strings.Contains(body, "Subject:") {
		t.Fatal("expected Subject header")
	}

	if !strings.Contains(body, "MIME-Version: 1.0") {
		t.Fatal("expected MIME-Version header")
	}

	if !strings.Contains(body, "Content-Type: multipart/alternative") {
		t.Fatal("expected multipart alternative content type")
	}

	if !strings.Contains(body, "Content-Type: text/plain; charset=UTF-8") {
		t.Fatal("expected text/plain part")
	}

	if !strings.Contains(body, "Content-Type: text/html; charset=UTF-8") {
		t.Fatal("expected text/html part")
	}

	if !strings.Contains(body, "plain text body") {
		t.Fatal("expected plain text body")
	}

	if !strings.Contains(body, "<p>html body</p>") {
		t.Fatal("expected html body")
	}
}

func TestSMTPMailService_buildMessage_MultipleRecipients(t *testing.T) {
	svc, err := NewSMTPMailService(validSMTPMailConfig(), zap.NewNop())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	msg, err := svc.buildMessage(
		[]string{"first@example.com", "second@example.com"},
		"Subject",
		"text",
		"<p>html</p>",
	)

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	body := string(msg)

	if !strings.Contains(body, "To: first@example.com, second@example.com") {
		t.Fatalf("expected multiple recipients in To header, got:\n%s", body)
	}
}

func TestSMTPMailService_buildMessage_FromNameEncoded(t *testing.T) {
	cfg := validSMTPMailConfig()
	cfg.FromName = "Сервис авторизации"

	svc, err := NewSMTPMailService(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	msg, err := svc.buildMessage(
		[]string{"user@example.com"},
		"Тема",
		"text",
		"<p>html</p>",
	)

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	body := string(msg)

	if !strings.Contains(body, "<noreply@example.com>") {
		t.Fatalf("expected from email in header, got:\n%s", body)
	}

	if !strings.Contains(body, "=?UTF-8?q?") {
		t.Fatalf("expected encoded UTF-8 header, got:\n%s", body)
	}
}

func TestSMTPMailService_buildMessage_WithoutFromName(t *testing.T) {
	cfg := validSMTPMailConfig()
	cfg.FromName = ""

	svc, err := NewSMTPMailService(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	msg, err := svc.buildMessage(
		[]string{"user@example.com"},
		"Subject",
		"text",
		"<p>html</p>",
	)

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	body := string(msg)

	if !strings.Contains(body, "From: noreply@example.com") {
		t.Fatalf("expected plain from email, got:\n%s", body)
	}
}
