package sender

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"notification/models"
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

func (s *Email) Send(_ context.Context, d *models.Delivery, n *models.Notification) (string, error) {
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

	if err := smtp.SendMail(
		s.address,
		auth,
		s.from,
		[]string{d.Recipient},
		msg,
	); err != nil {
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
