package sender

import (
	"context"
	"errors"
	"fmt"
	"net/smtp"
	"notification/models"
)

var ErrPermanent = errors.New("permanent delivery failure")

type Sender interface {
	Send(context.Context, *models.Delivery, *models.Notification) (string, error)
}
type Email struct{ address, from string }

func NewEmail(address, from string) *Email { return &Email{address: address, from: from} }
func (s *Email) Send(_ context.Context, d *models.Delivery, n *models.Notification) (string, error) {
	msg := []byte("From: " + s.from + "\r\nTo: " + d.Recipient + "\r\nSubject: " + n.Title + "\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + n.Body)
	return "", smtp.SendMail(s.address, nil, s.from, []string{d.Recipient}, msg)
}

type InApp struct{}

func (InApp) Send(context.Context, *models.Delivery, *models.Notification) (string, error) {
	return "websocket", nil
}

type Disabled struct{ Channel string }

func (s Disabled) Send(context.Context, *models.Delivery, *models.Notification) (string, error) {
	return "", fmt.Errorf("%s sender disabled", s.Channel)
}
