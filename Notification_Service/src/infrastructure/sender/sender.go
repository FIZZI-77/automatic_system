package sender

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"notification/models"
	"time"
)

var ErrPermanent = errors.New("permanent delivery failure")

type Sender interface {
	Send(context.Context, *models.Delivery, *models.Notification) (string, error)
}
type Email struct {
	address  string
	from     string
	username string
	password string
}

func NewEmail(address, from, username, password string) *Email {
	return &Email{
		address:  address,
		from:     from,
		username: username,
		password: password,
	}
}

func (s *Email) Send(ctx context.Context, d *models.Delivery, n *models.Notification) (string, error) {
	msg := []byte(
		"From: " + s.from +
			"\r\nTo: " + d.Recipient +
			"\r\nSubject: " + n.Title +
			"\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" +
			n.Body,
	)

	host, _, err := net.SplitHostPort(s.address)
	if err != nil {
		return "", fmt.Errorf("parse SMTP address: %w", err)
	}

	var auth smtp.Auth

	if s.username != "" {
		if s.password == "" {
			return "", errors.New("SMTP password is empty")
		}

		auth = smtp.PlainAuth(
			"",
			s.username,
			s.password,
			host,
		)
	}

	dialer := net.Dialer{Timeout: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", s.address)
	if err != nil {
		return "", fmt.Errorf("connect SMTP: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(30 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return "", fmt.Errorf("set SMTP deadline: %w", err)
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return "", fmt.Errorf("create SMTP client: %w", err)
	}
	defer client.Close()
	if auth != nil {
		if err = client.Auth(auth); err != nil {
			return "", fmt.Errorf("authenticate SMTP: %w", err)
		}
	}
	if err = client.Mail(s.from); err == nil {
		err = client.Rcpt(d.Recipient)
	}
	var writer io.WriteCloser
	if err == nil {
		writer, err = client.Data()
	}
	if err == nil {
		_, err = writer.Write(msg)
	}
	if writer != nil {
		err = errors.Join(err, writer.Close())
	}
	if err == nil {
		err = client.Quit()
	}
	if err != nil {
		return "", fmt.Errorf("send email: %w", err)
	}

	return "", nil
}

type InApp struct{}

func (InApp) Send(context.Context, *models.Delivery, *models.Notification) (string, error) {
	return "websocket", nil
}

type Disabled struct{ Channel string }

func (s Disabled) Send(context.Context, *models.Delivery, *models.Notification) (string, error) {
	return "", fmt.Errorf("%s sender disabled", s.Channel)
}
